package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/pisentry/pisentry/internal/config"
	"github.com/pisentry/pisentry/internal/rules"
)

// defaultBundleURL serves the bundle attached to the latest GitHub release.
const defaultBundleURL = "https://github.com/pisentry/pisentry/releases/latest/download/"

// cmdUpdatePatterns downloads a signed rule bundle and installs it into
// rules.d. Every check runs before anything is written; any failure exits 1
// and leaves rules.d as it was.
func cmdUpdatePatterns(args []string) error {
	fs := flag.NewFlagSet("update-patterns", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfig, "config file (JSON)")
	base := fs.String("url", defaultBundleURL, "HTTPS URL of the directory holding "+rules.ManifestName+", "+rules.SignatureName+" and the bundle files")
	dir := fs.String("rules", "", "install into this directory (default: rules.dir from the config)")
	noReload := fs.Bool("no-reload", false, "do not send SIGHUP to a running agent")
	if err := fs.Parse(args); err != nil {
		return err
	}
	target := *dir
	if target == "" {
		cfg, err := config.Load(*cfgPath)
		if err != nil {
			return err
		}
		target = cfg.Rules.Dir
	}
	if target == "" {
		return errors.New("rules.dir is empty; pass -rules DIR")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	u := &updater{client: bundleHTTPClient(), keys: rules.TrustedKeys(), now: time.Now, agentVersion: version, out: os.Stdout}
	installed, err := u.run(ctx, *base, target)
	if err != nil || !installed || *noReload {
		return err
	}
	switch n := signalAgents("/proc"); n {
	case 0:
		fmt.Println("no running agent found; it loads the bundle at start, or within rules.reload_interval")
	default:
		fmt.Printf("sent SIGHUP to %d running agent(s)\n", n)
	}
	return nil
}

type updater struct {
	client       *http.Client
	keys         []ed25519.PublicKey
	now          func() time.Time
	agentVersion string
	out          io.Writer
}

// run fetches and verifies the bundle at base and installs it into dir. It
// returns true when a new bundle was installed and false when dir already
// has this version.
func (u *updater) run(ctx context.Context, base, dir string) (bool, error) {
	bu, err := url.Parse(base)
	if err != nil {
		return false, fmt.Errorf("bundle url: %w", err)
	}
	if bu.Scheme != "https" || bu.Host == "" {
		return false, fmt.Errorf("bundle url %q: must be https://", base)
	}
	if len(u.keys) == 0 {
		return false, errors.New("this build trusts no bundle signing keys")
	}

	mb, err := u.fetch(ctx, bu, rules.ManifestName, rules.MaxManifestSize)
	if err != nil {
		return false, err
	}
	sb, err := u.fetch(ctx, bu, rules.SignatureName, rules.MaxSignatureSize)
	if errors.Is(err, errNotFound) {
		return false, fmt.Errorf("%w: no %s at %s", rules.ErrUnsigned, rules.SignatureName, base)
	}
	if err != nil {
		return false, err
	}
	m, err := rules.VerifyManifest(mb, sb, u.keys)
	if err != nil {
		return false, err
	}
	if err := m.CheckFresh(u.now()); err != nil {
		return false, err
	}
	have, err := rules.InstalledVersion(dir)
	if err != nil {
		return false, err
	}
	switch {
	case m.Version < have:
		return false, fmt.Errorf("%w: offered version %d, installed %d", rules.ErrOlderVersion, m.Version, have)
	case m.Version == have:
		fmt.Fprintf(u.out, "rule bundle version %d is already installed in %s\n", have, dir)
		return false, nil
	}
	if err := m.CheckAgent(u.agentVersion); err != nil {
		return false, err
	}

	files := make(map[string][]byte, len(m.Files))
	for _, f := range m.Files {
		b, err := u.fetch(ctx, bu, f.Name, rules.MaxFileSize)
		if err != nil {
			return false, err
		}
		if err := m.CheckFile(f.Name, b); err != nil {
			return false, err
		}
		if _, _, err := rules.LoadBytes(f.Name, b); err != nil {
			return false, err
		}
		files[f.Name] = b
	}
	if err := install(dir, m, mb, sb, files); err != nil {
		return false, fmt.Errorf("install into %s: %w", dir, err)
	}
	fmt.Fprintf(u.out, "installed rule bundle version %d (%d files, expires %s) into %s\n",
		m.Version, len(m.Files), m.Expires.UTC().Format(time.RFC3339), dir)
	return true, nil
}

var errNotFound = errors.New("not found")

func (u *updater) fetch(ctx context.Context, base *url.URL, name string, max int64) ([]byte, error) {
	ref := base.JoinPath(name).String()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ref, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "pisentry/"+version)
	resp, err := u.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, fmt.Errorf("%s: %w", ref, errNotFound)
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("%s: %s", ref, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ref, err)
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%s: larger than %d bytes", ref, max)
	}
	return b, nil
}

// bundleHTTPClient follows redirects (GitHub release downloads redirect to
// a CDN) but never off HTTPS.
func bundleHTTPClient() *http.Client {
	return &http.Client{
		Timeout: time.Minute,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "https" {
				return fmt.Errorf("redirect to %s refused: not https", req.URL.Redacted())
			}
			if len(via) >= 10 {
				return errors.New("too many redirects")
			}
			return nil
		},
	}
}

// install writes the bundle into dir. Every file is first written to a
// dotfile (which the loader skips) and synced, then renamed into place, the
// manifest last. bundle-*.json files the new manifest does not list are
// removed. A reload that lands mid-way sees a manifest that does not match
// the files and is rejected, keeping the previous rules; the agent waits for
// rules.d to settle before reloading, so in practice it sees the end state.
func install(dir string, m *rules.Manifest, manifest, sig []byte, files map[string][]byte) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	type staged struct{ tmp, final string }
	var done []staged
	defer func() {
		for _, s := range done {
			_ = os.Remove(s.tmp) // no-op once renamed
		}
	}()
	stage := func(name string, b []byte) error {
		f, err := os.CreateTemp(dir, ".bundle-*.tmp")
		if err != nil {
			return err
		}
		done = append(done, staged{f.Name(), filepath.Join(dir, name)})
		if _, err := f.Write(b); err != nil {
			f.Close()
			return err
		}
		if err := f.Chmod(0o644); err != nil {
			f.Close()
			return err
		}
		if err := f.Sync(); err != nil {
			f.Close()
			return err
		}
		return f.Close()
	}
	for _, f := range m.Files {
		if err := stage(f.Name, files[f.Name]); err != nil {
			return err
		}
	}
	if err := stage(rules.SignatureName, sig); err != nil {
		return err
	}
	if err := stage(rules.ManifestName, manifest); err != nil {
		return err
	}
	for _, s := range done {
		if err := os.Rename(s.tmp, s.final); err != nil {
			return err
		}
	}
	listed := map[string]bool{}
	for _, f := range m.Files {
		listed[f.Name] = true
	}
	old, _ := filepath.Glob(filepath.Join(dir, rules.BundleFilePrefix+"*.json"))
	for _, p := range old {
		if !listed[filepath.Base(p)] {
			if err := os.Remove(p); err != nil {
				return err
			}
		}
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}

// signalAgents sends SIGHUP to every `pisentry run` process found under
// procRoot and returns how many it signalled. The agent also notices the
// change on its own within rules.reload_interval; this just makes it
// immediate.
func signalAgents(procRoot string) int {
	n := 0
	for _, pid := range agentPIDs(procRoot, os.Getpid()) {
		p, err := os.FindProcess(pid)
		if err != nil {
			continue
		}
		if p.Signal(syscall.SIGHUP) == nil {
			n++
		}
	}
	return n
}

// agentPIDs lists the processes under procRoot whose command line is
// `pisentry run ...`, other than self.
func agentPIDs(procRoot string, self int) []int {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil
	}
	var pids []int
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == self {
			continue
		}
		b, err := os.ReadFile(filepath.Join(procRoot, e.Name(), "cmdline"))
		if err != nil {
			continue
		}
		argv := strings.Split(strings.TrimRight(string(b), "\x00"), "\x00")
		if len(argv) < 2 || filepath.Base(argv[0]) != "pisentry" || argv[1] != "run" {
			continue
		}
		pids = append(pids, pid)
	}
	return pids
}
