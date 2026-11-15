package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pisentry/pisentry/internal/rules"
)

var updNow = time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)

func updKey(seed byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
}

func ruleFile(t *testing.T, id string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"schema_version": 1,
		"rules": []any{map[string]any{
			"id": id, "title": "Test rule", "category": "PS04", "level": "high", "source": "log",
			"match": map[string]any{"all": []any{map[string]any{"field": "log.msg", "contains": []any{"evil"}}}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// bundleServer serves a bundle over HTTPS. Tests edit files to break it.
type bundleServer struct {
	*httptest.Server
	mu    sync.Mutex
	files map[string][]byte
}

func newBundleServer(t *testing.T) *bundleServer {
	bs := &bundleServer{files: map[string][]byte{}}
	bs.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bs.mu.Lock()
		b, ok := bs.files[strings.TrimPrefix(r.URL.Path, "/bundles/")]
		bs.mu.Unlock()
		if !ok || !strings.HasPrefix(r.URL.Path, "/bundles/") {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b)
	}))
	t.Cleanup(bs.Close)
	return bs
}

func (bs *bundleServer) url() string { return bs.URL + "/bundles/" }

// publish replaces the served bundle with a signed one.
func (bs *bundleServer) publish(t *testing.T, key ed25519.PrivateKey, version uint64, expires time.Time, files map[string][]byte) {
	t.Helper()
	m := rules.Manifest{
		SchemaVersion: rules.ManifestSchemaVersion, Version: version,
		Created: expires.Add(-90 * 24 * time.Hour), Expires: expires,
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		sum := sha256.Sum256(files[n])
		m.Files = append(m.Files, rules.ManifestFile{Name: n, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(files[n]))})
	}
	mb, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	sb, err := rules.SignManifest(mb, key)
	if err != nil {
		t.Fatal(err)
	}
	bs.mu.Lock()
	defer bs.mu.Unlock()
	bs.files = map[string][]byte{rules.ManifestName: mb, rules.SignatureName: sb}
	for n, b := range files {
		bs.files[n] = b
	}
}

func (bs *bundleServer) set(name string, b []byte) {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	if b == nil {
		delete(bs.files, name)
		return
	}
	bs.files[name] = b
}

func newUpdater(bs *bundleServer, keys ...ed25519.PrivateKey) *updater {
	u := &updater{client: bs.Client(), now: func() time.Time { return updNow }, agentVersion: "v0.2.2", out: io.Discard}
	for _, k := range keys {
		u.keys = append(u.keys, k.Public().(ed25519.PublicKey))
	}
	return u
}

// snapshot reads every file in dir, so a test can prove a rejected update
// wrote nothing.
func snapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return out
	}
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		out[e.Name()] = string(b)
	}
	return out
}

func TestUpdatePatternsInstalls(t *testing.T) {
	cur, next := updKey(1), updKey(2)
	bs := newBundleServer(t)
	dir := filepath.Join(t.TempDir(), "rules.d")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	operator := ruleFile(t, "LOCAL-RULE")
	if err := os.WriteFile(filepath.Join(dir, "local.json"), operator, 0o644); err != nil {
		t.Fatal(err)
	}
	u := newUpdater(bs, cur, next)
	ctx := context.Background()

	bs.publish(t, cur, 5, updNow.Add(24*time.Hour), map[string][]byte{
		"bundle-ssh.json": ruleFile(t, "PACK-SSH"),
		"bundle-old.json": ruleFile(t, "PACK-OLD"),
	})
	if ok, err := u.run(ctx, bs.url(), dir); err != nil || !ok {
		t.Fatalf("install: %v %v", ok, err)
	}
	m, err := rules.VerifyDir(dir, u.keys)
	if err != nil || m == nil || m.Version != 5 {
		t.Fatalf("installed bundle does not verify: %v %v", m, err)
	}

	// Same version again: nothing to do, not an error.
	before := snapshot(t, dir)
	if ok, err := u.run(ctx, bs.url(), dir); err != nil || ok {
		t.Fatalf("same version: %v %v", ok, err)
	}
	if !reflect.DeepEqual(before, snapshot(t, dir)) {
		t.Fatal("same version rewrote rules.d")
	}

	// A newer bundle signed with the next key replaces the files it no
	// longer lists and leaves operator files alone.
	bs.publish(t, next, 6, updNow.Add(24*time.Hour), map[string][]byte{"bundle-ssh.json": ruleFile(t, "PACK-SSH-V2")})
	if ok, err := u.run(ctx, bs.url(), dir); err != nil || !ok {
		t.Fatalf("update: %v %v", ok, err)
	}
	got := snapshot(t, dir)
	var names []string
	for n := range got {
		names = append(names, n)
	}
	sort.Strings(names)
	want := []string{"bundle-ssh.json", rules.ManifestName, rules.SignatureName, "local.json"}
	sort.Strings(want)
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("rules.d has %v, want %v", names, want)
	}
	if got["local.json"] != string(operator) {
		t.Fatal("operator file changed")
	}
	if v, _ := rules.InstalledVersion(dir); v != 6 {
		t.Fatalf("installed version %d", v)
	}
}

// Each rejection exits non-zero (cmdUpdatePatterns returns the error, main
// exits 1) and leaves rules.d exactly as it was.
func TestUpdatePatternsRejects(t *testing.T) {
	cur, stranger := updKey(1), updKey(9)
	good := map[string][]byte{"bundle-ssh.json": ruleFile(t, "PACK-SSH")}
	later := updNow.Add(24 * time.Hour)

	cases := []struct {
		name  string
		setup func(t *testing.T, bs *bundleServer, u *updater)
		url   func(bs *bundleServer) string
		want  error
	}{
		{
			name: "unsigned",
			setup: func(t *testing.T, bs *bundleServer, u *updater) {
				bs.publish(t, cur, 5, later, good)
				bs.set(rules.SignatureName, nil)
			},
			want: rules.ErrUnsigned,
		},
		{
			name: "unknown key",
			setup: func(t *testing.T, bs *bundleServer, u *updater) {
				bs.publish(t, stranger, 5, later, good)
			},
			want: rules.ErrUnknownKey,
		},
		{
			name: "bad signature",
			setup: func(t *testing.T, bs *bundleServer, u *updater) {
				bs.publish(t, cur, 5, later, good)
				bs.mu.Lock()
				bs.files[rules.ManifestName] = bytes.Replace(bs.files[rules.ManifestName], []byte(`"version":5`), []byte(`"version":50`), 1)
				bs.mu.Unlock()
			},
			want: rules.ErrBadSignature,
		},
		{
			name: "tampered file",
			setup: func(t *testing.T, bs *bundleServer, u *updater) {
				bs.publish(t, cur, 5, later, good)
				bs.set("bundle-ssh.json", ruleFile(t, "PACK-EVIL"))
			},
			want: rules.ErrHashMismatch,
		},
		{
			name: "older version",
			setup: func(t *testing.T, bs *bundleServer, u *updater) {
				bs.publish(t, cur, 3, later, good)
			},
			want: rules.ErrOlderVersion,
		},
		{
			name: "expired manifest",
			setup: func(t *testing.T, bs *bundleServer, u *updater) {
				bs.publish(t, cur, 5, updNow, good)
			},
			want: rules.ErrExpired,
		},
		{
			name: "agent too old",
			setup: func(t *testing.T, bs *bundleServer, u *updater) {
				bs.publish(t, cur, 5, later, good)
				u.agentVersion = "v0.2.1"
				// re-sign with a min_agent_version
				var m rules.Manifest
				_ = json.Unmarshal(bs.files[rules.ManifestName], &m)
				m.MinAgentVersion = "v0.2.2"
				mb, _ := json.Marshal(m)
				sb, _ := rules.SignManifest(mb, cur)
				bs.set(rules.ManifestName, mb)
				bs.set(rules.SignatureName, sb)
			},
			want: rules.ErrAgentTooOld,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bs := newBundleServer(t)
			u := newUpdater(bs, cur)
			dir := t.TempDir()
			// Version 4 is installed.
			bs.publish(t, cur, 4, later, map[string][]byte{"bundle-ssh.json": ruleFile(t, "PACK-SSH-V4")})
			if _, err := u.run(context.Background(), bs.url(), dir); err != nil {
				t.Fatal(err)
			}
			before := snapshot(t, dir)

			tc.setup(t, bs, u)
			ok, err := u.run(context.Background(), bs.url(), dir)
			if !errors.Is(err, tc.want) || ok {
				t.Fatalf("got %v (installed=%v), want %v", err, ok, tc.want)
			}
			if !reflect.DeepEqual(before, snapshot(t, dir)) {
				t.Fatal("rejected bundle changed rules.d")
			}
		})
	}
}

func TestUpdatePatternsRejectsOther(t *testing.T) {
	cur := updKey(1)
	later := updNow.Add(24 * time.Hour)
	bs := newBundleServer(t)
	dir := t.TempDir()

	if _, err := newUpdater(bs, cur).run(context.Background(), "http://example.invalid/", dir); err == nil {
		t.Fatal("plain http accepted")
	}
	if _, err := newUpdater(bs).run(context.Background(), bs.url(), dir); err == nil {
		t.Fatal("ran with no trusted keys")
	}

	// Correctly signed and hashed, but not a valid rule file.
	bad := []byte(`{"schema_version":1,"rules":[{"id":"x"}]}`)
	bs.publish(t, cur, 5, later, map[string][]byte{"bundle-bad.json": bad})
	if _, err := newUpdater(bs, cur).run(context.Background(), bs.url(), dir); err == nil {
		t.Fatal("invalid rule file installed")
	}
	if len(snapshot(t, dir)) != 0 {
		t.Fatal("rejected bundle wrote files")
	}

	bs.publish(t, cur, 5, later, map[string][]byte{"bundle-ssh.json": ruleFile(t, "PACK-SSH")})
	bs.set("bundle-ssh.json", nil)
	if _, err := newUpdater(bs, cur).run(context.Background(), bs.url(), dir); err == nil {
		t.Fatal("missing file accepted")
	}
}

func TestAgentPIDs(t *testing.T) {
	root := t.TempDir()
	write := func(pid, cmdline string) {
		if err := os.MkdirAll(filepath.Join(root, pid), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, pid, "cmdline"), []byte(cmdline), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("10", "/usr/local/bin/pisentry\x00run\x00-config\x00/etc/pisentry/config.json\x00")
	write("11", "pisentry\x00update-patterns\x00")
	write("12", "/usr/bin/vim\x00pisentry\x00run\x00")
	write("13", "pisentry\x00run\x00") // self
	write("self", "pisentry\x00run\x00")
	got := agentPIDs(root, 13)
	if !reflect.DeepEqual(got, []int{10}) {
		t.Fatalf("got %v, want [10]", got)
	}
	if agentPIDs(filepath.Join(root, "missing"), 0) != nil {
		t.Fatal("missing proc root")
	}
}
