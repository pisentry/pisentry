#!/usr/bin/env python3
"""Build the pisentry website from site/ into an output directory.

Standard library only. It copies site/ (skipping names that start with "_"),
copies the brand assets from docs/assets/, fills shared partials, and renders
live numbers and the roadmap from the GitHub API into static HTML, so the
published pages need no client-side fetches.

Usage:
  python3 scripts/build-site.py --out _site            # live data, unauthenticated is fine locally
  python3 scripts/build-site.py --out _site --offline  # no network, fallback text stays
  GH_TOKEN=... python3 scripts/build-site.py --out _site --strict   # CI: API errors fail the build

Every string that comes from the API is HTML-escaped before it is placed in a
page. Issue text is only taken from issues that carry a milestone, which only
maintainers can set.
"""

import argparse
import datetime as dt
import html
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SITE = ROOT / "site"
BRAND = ROOT / "docs" / "assets"
BRAND_FILES = [
    "pisentry-logo-horizontal-dark.svg",
    "pisentry-logo-horizontal-light.svg",
    "pisentry-mark-dark.svg",
    "pisentry-mark-light.svg",
    "grafana-top10.png",
    "demo-live.gif",
    "social-preview.png",
]
API = "https://api.github.com"
SCORECARD = "https://api.securityscorecards.dev/projects/github.com/"
BANNED = {"\u2014": "em dash", "\u2013": "en dash"}


def log(msg):
    print(f"build-site: {msg}", file=sys.stderr)


# ---------------------------------------------------------------- fetching

def get_json(url, token=None):
    """GET a JSON document, following GitHub pagination. Returns (data, error)."""
    out = None
    while url:
        req = urllib.request.Request(url, headers={
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "pisentry-site-build",
        })
        if token and url.startswith(API):
            req.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                body = json.load(resp)
                link = resp.headers.get("Link", "")
        except urllib.error.HTTPError as e:
            return None, f"{url}: HTTP {e.code}"
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
            return None, f"{url}: {e}"
        if isinstance(body, list):
            out = (out or []) + body
        else:
            return body, None
        m = re.search(r'<([^>]+)>;\s*rel="next"', link)
        url = m.group(1) if m else None
    return out, None


def collect(repo, token, offline, strict):
    data = {"repo": repo}
    if offline:
        return data
    errors = []

    def need(key, url):
        val, err = get_json(url, token)
        if err:
            errors.append(err)
        else:
            data[key] = val

    need("repo_info", f"{API}/repos/{repo}")
    rel, err = get_json(f"{API}/repos/{repo}/releases/latest", token)
    if err and "HTTP 404" not in err:
        errors.append(err)
    elif rel:
        data["release"] = rel
    need("milestones", f"{API}/repos/{repo}/milestones?state=all&per_page=100&sort=due_on")
    need("issues", f"{API}/repos/{repo}/issues?state=all&milestone=*&per_page=100")

    sc, err = get_json(SCORECARD + repo)
    if err:
        log(f"scorecard unavailable, keeping fallback ({err})")
    else:
        data["scorecard"] = sc

    for e in errors:
        log(f"API error: {e}")
    if errors and strict:
        sys.exit(1)
    return data


def repo_stats():
    loc = 0
    for base in ("cmd", "internal"):
        for p in (ROOT / base).rglob("*.go"):
            if not p.name.endswith("_test.go"):
                loc += sum(1 for _ in p.open(encoding="utf-8"))
    gomod = (ROOT / "go.mod").read_text(encoding="utf-8")
    requires = 0
    in_block = False
    for line in gomod.splitlines():
        s = line.strip()
        if s.startswith("require ("):
            in_block = True
            continue
        if in_block:
            if s == ")":
                in_block = False
            elif s and not s.startswith("//"):
                requires += 1
        elif s.startswith("require "):
            requires += 1
    sha = os.environ.get("GITHUB_SHA", "")
    if not sha:
        try:
            sha = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"],
                                 capture_output=True, text=True, check=True).stdout.strip()
        except (OSError, subprocess.CalledProcessError):
            sha = ""
    return {"go_loc": loc, "modules": requires, "sha": sha[:7]}


# ---------------------------------------------------------------- helpers

def esc(s):
    return html.escape(str(s), quote=True)


def inline(s):
    """Escape, then turn `code` spans into <code>. Safe: input is escaped first."""
    return re.sub(r"`([^`]+)`", r"<code>\1</code>", esc(s))


def strip_md_links(s):
    return re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", s)


def cut(s, n):
    s = re.sub(r"\s+", " ", s).strip()
    if len(s) <= n:
        return s
    s = s[:n]
    return s[: s.rfind(" ")].rstrip(",;:") + "..."


def context_of(body):
    if not body:
        return ""
    m = re.search(r"###\s*Context\s*\n(.*?)(?:\n###|\Z)", body, re.S)
    text = m.group(1) if m else body
    return cut(strip_md_links(text), 320)


def split_title(title):
    m = re.match(r"^\[([A-Z0-9/ -]{2,16})\]\s*(.*)$", title)
    return (m.group(1), m.group(2)) if m else ("", title)


def split_milestone(title):
    code, sep, name = title.partition(": ")
    return (code, name) if sep else ("", title)


def date_only(ts):
    return ts[:10] if ts else ""


# ---------------------------------------------------------------- CHANGELOG

def changelog():
    path = ROOT / "CHANGELOG.md"
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8")
    out = []
    for chunk in re.split(r"^## \[", text, flags=re.M)[1:]:
        head, _, rest = chunk.partition("\n")
        m = re.match(r"([^\]]+)\](?:\s*-\s*(\S+))?", head)
        if not m:
            continue
        version, date = m.group(1), m.group(2) or ""
        items = []
        for line in rest.splitlines():
            if line.startswith("[") and "]: http" in line:
                break
            if line.startswith("- "):
                items.append(short_bullet(line[2:]))
        out.append({"version": version, "date": date, "items": items})
    return out


def short_bullet(s):
    s = strip_md_links(s).strip()
    head, sep, tail = s.partition(": ")
    if sep:
        # "`path`: what it is" -> the description. "Commands: a, b" -> keep both.
        # A long lead-in such as "Ten detection categories, PS01 to PS10: ..." -> the lead-in.
        if head.startswith("`"):
            s = tail
        elif " " in head and len(head) >= 24:
            s = head
    s = cut(s, 110)
    return s[:1].upper() + s[1:]


# ---------------------------------------------------------------- docs

# docs/*.md rendered as site pages, in nav order. Only the Markdown these files
# use is supported: headings, paragraphs, flat lists, fenced code, pipe tables,
# and inline code, links and bold. The files live in the repo, but everything is
# escaped anyway.
DOCS = ROOT / "docs"
DOC_PAGES = ["install", "reference", "rule-schema", "event-schema"]
DOC_FILES = ["event-schema.json"]  # served at the root, where its $id points


def slug(text):
    """GitHub's heading anchor: lowercase, punctuation dropped, spaces to dashes."""
    text = re.sub(r"[`*]", "", text).strip().lower()
    return re.sub(r"[^\w\- ]", "", text).replace(" ", "-")


def doc_link(href, repo):
    if re.match(r"^(https?:|mailto:|#)", href):
        return href
    path, sep, frag = href.partition("#")
    frag = sep + frag
    name = Path(path).stem
    if path.endswith(".md") and "/" not in path and name in DOC_PAGES:
        return f"{name}.html{frag}"
    if path in DOC_FILES:
        return path + frag
    target = path[3:] if path.startswith("../") else f"docs/{path}"
    return f"https://github.com/{repo}/blob/main/{target}{frag}"


def md_inline(s, repo):
    stash = []

    def keep(h):
        stash.append(h)
        return f"\x00{len(stash) - 1}\x00"

    s = re.sub(r"`([^`]+)`", lambda m: keep(f"<code>{esc(m.group(1))}</code>"), s)

    def text(t):
        return re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", esc(t))

    s = re.sub(r"\[([^\]]+)\]\(([^)\s]+)\)",
               lambda m: keep(f'<a href="{esc(doc_link(m.group(2), repo))}">{text(m.group(1))}</a>'), s)
    s = text(s)
    while "\x00" in s:
        s = re.sub(r"\x00(\d+)\x00", lambda m: stash[int(m.group(1))], s)
    return s


def table_cells(line):
    """Split a pipe-table row. A | inside `code` or escaped as \\| is not a separator."""
    cells, cur, in_code, i = [], "", False, 0
    line = line.strip()
    if line.startswith("|"):
        line = line[1:]
    if line.endswith("|") and not line.endswith("\\|"):
        line = line[:-1]
    while i < len(line):
        c = line[i]
        if c == "\\" and line[i + 1:i + 2] == "|":
            cur += "|"
            i += 2
            continue
        if c == "`":
            in_code = not in_code
        if c == "|" and not in_code:
            cells.append(cur.strip())
            cur = ""
        else:
            cur += c
        i += 1
    cells.append(cur.strip())
    return cells


def md_blocks(text, repo):
    """Markdown to (title, lead, body HTML, [(id, h2 text)])."""
    lines = text.replace("\r\n", "\n").split("\n")
    title, lead, out, toc = "", "", [], []
    para, i = [], 0

    def flush():
        nonlocal lead
        if para:
            html_ = md_inline(" ".join(para), repo)
            if title and not lead and not out:
                lead = html_
            else:
                out.append(f"<p>{html_}</p>")
            para.clear()

    while i < len(lines):
        line = lines[i]
        if line.startswith("```"):
            flush()
            j = i + 1
            while j < len(lines) and not lines[j].startswith("```"):
                j += 1
            code = "\n".join(lines[i + 1:j])
            out.append(f'<div class="code"><button class="copy" type="button" data-copy>Copy</button><pre>{esc(code)}</pre></div>')
            i = j + 1
            continue
        m = re.match(r"^(#{1,4}) (.*)$", line)
        if m:
            flush()
            level, raw = len(m.group(1)), m.group(2).strip()
            if level == 1 and not title:
                title = re.sub(r"[`*]", "", raw)
            else:
                hid = slug(raw)
                out.append(f'<h{level} id="{esc(hid)}">{md_inline(raw, repo)}</h{level}>')
                if level == 2:
                    toc.append((hid, re.sub(r"[`*]", "", raw)))
            i += 1
            continue
        if line.startswith("|"):
            flush()
            rows = []
            while i < len(lines) and lines[i].startswith("|"):
                rows.append(table_cells(lines[i]))
                i += 1
            head, body = rows[0], [r for r in rows[1:] if not all(re.fullmatch(r":?-+:?", c) for c in r)]
            ths = "".join(f'<th scope="col">{md_inline(c, repo)}</th>' for c in head)
            trs = "".join("<tr>" + "".join(f"<td>{md_inline(c, repo)}</td>" for c in r) + "</tr>" for r in body)
            out.append(f'<div class="table-wrap"><table><thead><tr>{ths}</tr></thead><tbody>{trs}</tbody></table></div>')
            continue
        lm = re.match(r"^(-|\d+\.) (.*)$", line)
        if lm:
            flush()
            tag = "ul" if lm.group(1) == "-" else "ol"
            items = []
            while i < len(lines):
                im = re.match(r"^(-|\d+\.) (.*)$", lines[i])
                if im:
                    items.append(im.group(2))
                elif lines[i].startswith("  ") and lines[i].strip() and items:
                    items[-1] += " " + lines[i].strip()
                else:
                    break
                i += 1
            # A list of in-page links is a table of contents; the page has its own.
            if not all(re.fullmatch(r"\[[^\]]+\]\(#[^)]+\)", it.strip()) for it in items):
                out.append(f"<{tag}>" + "".join(f"<li>{md_inline(it, repo)}</li>" for it in items) + f"</{tag}>")
            continue
        if not line.strip():
            flush()
        else:
            para.append(line.strip())
        i += 1
    flush()
    return title, lead, "\n".join(out), toc


def render_docs(out, repo):
    pages = {}
    for name in DOC_PAGES:
        pages[name] = md_blocks((DOCS / f"{name}.md").read_text(encoding="utf-8"), repo)
    for f in DOC_FILES:
        shutil.copy2(DOCS / f, out / f)
    for name, (title, lead, body, toc) in pages.items():
        nav = []
        for other in DOC_PAGES:
            cur = ' aria-current="page"' if other == name else ""
            nav.append(f'<a href="{other}.html"{cur}>{esc(pages[other][0])}</a>')
            if other == name:
                nav += [f'<a class="sub" href="#{esc(hid)}">{esc(h)}</a>' for hid, h in toc]
        desc = cut(html.unescape(re.sub(r"<[^>]+>", "", lead)), 155)
        url = f"https://pisentry.dev/{name}.html"
        page = f"""<!doctype html>
<html lang="en">
<head>
<!-- include:head -->
<title>{esc(title)}: pisentry docs</title>
<meta name="description" content="{esc(desc)}">
<link rel="canonical" href="{url}">
<meta property="og:title" content="{esc(title)}">
<meta property="og:description" content="{esc(desc)}">
<meta property="og:url" content="{url}">
</head>
<body>
<a class="skip" href="#main">Skip to content</a>
<!-- include:header -->

<main id="main">
  <section class="page-head">
    <div class="wrap">
      <p class="eyebrow"><span class="sq"></span>Docs</p>
      <h1>{esc(title)}</h1>
      <p class="lead">{lead}</p>
    </div>
  </section>

  <div class="wrap with-toc">
    <nav class="toc" aria-label="Documentation">
      {chr(10).join(nav)}
    </nav>

    <div class="prose">
{body}
      <p class="muted doc-source">Source: <a href="https://github.com/{esc(repo)}/blob/main/docs/{name}.md">docs/{name}.md</a></p>
    </div>
  </div>
</main>

<!-- include:footer -->
</body>
</html>
"""
        (out / f"{name}.html").write_text(page, encoding="utf-8")


# ---------------------------------------------------------------- rendering

PRIO_RE = re.compile(r"priority:(P\d)")


def issue_model(i):
    labels = [l["name"] for l in i.get("labels", [])]
    prio = ""
    for l in labels:
        m = PRIO_RE.match(l)
        if m:
            prio = m.group(1)
    areas = [l.split(":", 1)[1] for l in labels if l.startswith("area:")]
    extra = []
    if "arch:arm-verified" in labels:
        extra.append("ARM verified")
    if "type:k8s-edge" in labels:
        extra.append("k3s")
    kind, title = split_title(i["title"])
    return {
        "number": i["number"], "title": title, "kind": kind, "state": i["state"],
        "prio": prio, "areas": areas, "extra": extra, "url": i["html_url"],
        "context": context_of(i.get("body") or ""),
        "milestone": (i.get("milestone") or {}).get("number"),
    }


def milestone_order(m):
    """Sort by the version in the title (v0.2.0 before v0.10.0), then by number.
    Milestone numbers never change, so renaming a milestone must not reorder by age."""
    v = re.search(r"v(\d+)\.(\d+)\.(\d+)", m["title"])
    return (0, tuple(int(x) for x in v.groups()), m["number"]) if v else (1, (), m["number"])


def build_model(data):
    ms = sorted(data.get("milestones") or [], key=milestone_order)
    issues = [issue_model(i) for i in (data.get("issues") or []) if "pull_request" not in i and i.get("milestone")]
    by_ms = {}
    for i in issues:
        by_ms.setdefault(i["milestone"], []).append(i)
    order = {"P0": 0, "P1": 1, "P2": 2, "": 3}
    model = []
    for m in ms:
        its = sorted(by_ms.get(m["number"], []), key=lambda i: (i["state"] == "closed", order.get(i["prio"], 3), i["number"]))
        total = m["open_issues"] + m["closed_issues"]
        code, name = split_milestone(m["title"])
        model.append({
            "number": m["number"], "code": code, "name": name, "description": m.get("description") or "",
            "state": m["state"], "url": m["html_url"], "due": date_only(m.get("due_on")),
            "open": m["open_issues"], "closed": m["closed_issues"], "total": total,
            "pct": round(100 * m["closed_issues"] / total) if total else 0, "issues": its,
        })
    return model


def progress_svg(pct):
    return (f'<svg class="progress" viewBox="0 0 100 8" preserveAspectRatio="none" aria-hidden="true">'
            f'<rect class="bar-fg" width="{pct}" height="8"/></svg>')


def render_teaser(model, log_entries, repo):
    rows = []
    shipped = [e for e in log_entries if e["version"] != "Unreleased"]
    if shipped:
        e = shipped[0]
        rows.append(
            f'<a class="ms" href="https://github.com/{esc(repo)}/releases/tag/v{esc(e["version"])}">'
            f'<span class="ms-code">v{esc(e["version"])}</span>'
            f'<span><span class="ms-title">Shipped</span><span class="ms-desc">{esc(e["date"])}. '
            f'{inline(e["items"][0]) if e["items"] else ""}</span></span>'
            f'<span class="ms-prog"><span class="count">released</span>{progress_svg(100)}</span></a>')
    for m in model:
        rows.append(
            f'<a class="ms" href="roadmap.html#m{m["number"]}">'
            f'<span class="ms-code">{esc(m["code"] or "M" + str(m["number"]))}</span>'
            f'<span><span class="ms-title">{esc(m["name"])}</span><span class="ms-desc">{inline(m["description"])}</span></span>'
            f'<span class="ms-prog"><span class="count">{m["closed"]} of {m["total"]} done</span>{progress_svg(m["pct"])}</span></a>')
    return '<div class="ms-list">' + "".join(rows) + "</div>"


def render_summary(model, data):
    total = sum(m["total"] for m in model)
    closed = sum(m["closed"] for m in model)
    tag = (data.get("release") or {}).get("tag_name", "")
    now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    parts = [f"<span><b>{len(model)}</b> milestones</span>",
             f"<span><b>{closed}</b> of <b>{total}</b> issues closed</span>"]
    if tag:
        parts.append(f"<span>Latest release <b>{esc(tag)}</b></span>")
    parts.append(f"<span>Updated <b>{esc(now)}</b></span>")
    return '<div class="rm-summary">' + "".join(parts) + "</div>"


def render_roadmap(model, log_entries, repo):
    out = []
    areas = {}
    for m in model:
        for i in m["issues"]:
            for a in i["areas"]:
                areas[a] = areas.get(a, 0) + 1
    f = ['<div class="filters" data-filters hidden>',
         '<span class="label">Area</span>',
         '<button class="fbtn" type="button" data-f="area" data-v="all" aria-pressed="true">All</button>']
    for a in sorted(areas, key=lambda a: (-areas[a], a)):
        f.append(f'<button class="fbtn" type="button" data-f="area" data-v="{esc(a)}" aria-pressed="false">{esc(a)}</button>')
    f += ['<span class="sep" aria-hidden="true"></span><span class="label">Priority</span>',
          '<button class="fbtn" type="button" data-f="prio" data-v="all" aria-pressed="true">All</button>']
    for p in ("P0", "P1", "P2"):
        f.append(f'<button class="fbtn" type="button" data-f="prio" data-v="{p}" aria-pressed="false">{p}</button>')
    f += ['<span class="sep" aria-hidden="true"></span>',
          '<button class="fbtn" type="button" data-f="closed" aria-pressed="false">Hide done</button>', "</div>"]
    out.append("".join(f))

    out.append('<div class="timeline">')
    for e in reversed(log_entries):  # oldest release first, then main, then milestones
        if not e["items"]:
            continue
        if e["version"] == "Unreleased":
            title, chip, link = "On main, in the next release", '<span class="state state-open">unreleased</span>', \
                f'https://github.com/{esc(repo)}/blob/main/CHANGELOG.md'
            code = "main"
        else:
            title, chip, link = f'Released {esc(e["date"])}', '<span class="state state-shipped">shipped</span>', \
                f'https://github.com/{esc(repo)}/releases/tag/v{esc(e["version"])}'
            code = "v" + e["version"]
        items = "".join(f"<li>{inline(x)}</li>" for x in e["items"][:8])
        if len(e["items"]) > 8:
            items += f'<li><a href="{link}">And {len(e["items"]) - 8} more changes and fixes</a></li>'
        out.append(
            f'<article class="mcard shipped"><div class="mcard-head"><div>'
            f'<div><span class="ms-code">{esc(code)}</span> {chip}</div><h2>{title}</h2></div>'
            f'<div class="mcard-meta"><a href="{link}">Details on GitHub</a></div></div><ul>{items}</ul></article>')

    for m in model:
        due = f'<div class="count"><span>Due</span><span>{esc(m["due"])}</span></div>' if m["due"] else ""
        state = "state-closed" if m["state"] == "closed" else "state-open"
        lis = []
        for i in m["issues"]:
            labels = ""
            if i["prio"]:
                labels += f'<span class="prio prio-{esc(i["prio"])}">{esc(i["prio"])}</span>'
            for a in i["areas"] + i["extra"]:
                labels += f'<span class="tag">{esc(a)}</span>'
            kind = f'<span class="itype">{esc(i["kind"])}</span>' if i["kind"] else ""
            body = f'<p>{inline(i["context"])}</p>' if i["context"] else ""
            cls = "issue closed" if i["state"] == "closed" else "issue"
            lis.append(
                f'<li class="{cls}" data-issue data-area="{esc(" ".join(i["areas"]))}" data-prio="{esc(i["prio"])}" data-state="{esc(i["state"])}">'
                f'<details><summary><span class="box" aria-hidden="true"></span><span class="inum">#{i["number"]}</span>'
                f'<span class="ititle">{kind}{inline(i["title"])}</span><span class="ilabels">{labels}</span></summary>'
                f'<div class="ibody">{body}<p><a href="{esc(i["url"])}">Open #{i["number"]} on GitHub</a></p></div></details></li>')
        issues = f'<ul class="issues">{"".join(lis)}</ul>' if lis else '<p class="empty">No issues yet.</p>'
        out.append(
            f'<article class="mcard" data-milestone id="m{m["number"]}"><div class="mcard-head"><div>'
            f'<div><span class="ms-code">{esc(m["code"] or "M" + str(m["number"]))}</span> '
            f'<span class="state {state}">{esc(m["state"])}</span></div>'
            f'<h2>{esc(m["name"])}</h2><p>{inline(m["description"])}</p></div>'
            f'<div class="mcard-meta"><div class="count"><span>{m["closed"]} of {m["total"]} done</span><span>{m["pct"]}%</span></div>'
            f'{progress_svg(m["pct"])}{due}<a href="{esc(m["url"])}">Milestone on GitHub</a></div></div>{issues}</article>')
    out.append("</div>")
    return "\n".join(out)


def values(data, stats):
    v = {"go_loc": f'{stats["go_loc"]:,}', "modules": str(stats["modules"])}
    info = data.get("repo_info") or {}
    if "stargazers_count" in info:
        v["stars"] = str(info["stargazers_count"])
    rel = data.get("release") or {}
    if rel.get("tag_name"):
        v["release_tag"] = rel["tag_name"]
        v["release_date"] = date_only(rel.get("published_at"))
        for a in rel.get("assets", []):
            if a["name"] == "pisentry-linux-arm64":
                v["arm64_mb"] = f'{a["size"] / 1e6:.1f}'
    sc = data.get("scorecard") or {}
    if isinstance(sc.get("score"), (int, float)):
        v["scorecard"] = f'{sc["score"]:.1f}'
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")
    v["generated"] = f'on {stamp} from {stats["sha"]}' if stats["sha"] else f"on {stamp}"
    return v


def fill(page, name, partials, vals, blocks):
    for key, body in partials.items():
        page = page.replace(f"<!-- include:{key} -->", body)
    current = {"security.html": 'href="security.html"', "roadmap.html": 'href="roadmap.html"'}.get(name)
    if current:
        page = page.replace(f'<a {current}>', f'<a {current} aria-current="page">', 1)

    page = re.sub(r'(<(\w+)[^>]*\bdata-build="(\w+)"[^>]*>)([^<]*)(</\2>)',
                  lambda m: m.group(1) + (esc(vals[m.group(3)]) if m.group(3) in vals else m.group(4)) + m.group(5), page)
    for key, body in blocks.items():
        page = re.sub(rf"<!-- build:{key} -->.*?<!-- /build:{key} -->", lambda _: body, page, flags=re.S)
    return page


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="_site")
    ap.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", "pisentry/pisentry"))
    ap.add_argument("--offline", action="store_true", help="no network; keep fallback text")
    ap.add_argument("--strict", action="store_true", help="fail on GitHub API errors (CI)")
    args = ap.parse_args()

    out = Path(args.out).resolve()
    if out in (ROOT, SITE) or SITE in out.parents or out == Path("/"):
        sys.exit(f"build-site: refusing to write to {out}")
    if out.exists():
        shutil.rmtree(out)
    shutil.copytree(SITE, out, ignore=lambda d, names: [n for n in names if n.startswith("_")])
    (out / "assets" / "brand").mkdir(parents=True, exist_ok=True)
    for f in BRAND_FILES:
        shutil.copy2(BRAND / f, out / "assets" / "brand" / f)
    render_docs(out, args.repo)

    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    data = collect(args.repo, token, args.offline, args.strict)
    stats = repo_stats()
    vals = values(data, stats)
    log_entries = changelog()
    blocks = {}
    if "milestones" in data and "issues" in data:
        model = build_model(data)
        blocks["roadmap-teaser"] = render_teaser(model, log_entries, args.repo)
        blocks["roadmap-summary"] = render_summary(model, data)
        blocks["roadmap"] = render_roadmap(model, log_entries, args.repo)
        public = {"generated": vals["generated"], "milestones": model, "changelog": log_entries}
        (out / "roadmap.json").write_text(json.dumps(public, indent=1), encoding="utf-8")

    partials = {p.stem: p.read_text(encoding="utf-8").rstrip("\n") for p in (SITE / "_partials").glob("*.html")}
    bad = False
    for page in sorted(out.glob("*.html")):
        text = fill(page.read_text(encoding="utf-8"), page.name, partials, vals, blocks)
        if "<!-- include:" in text:
            log(f"{page.name}: unresolved include")
            bad = True
        for ch, name in BANNED.items():
            if ch in text:
                log(f"{page.name}: contains an {name}")
                bad = True
        page.write_text(text, encoding="utf-8")
    if bad:
        sys.exit(1)
    log(f"wrote {out} ({', '.join(sorted(vals))})")


if __name__ == "__main__":
    main()
