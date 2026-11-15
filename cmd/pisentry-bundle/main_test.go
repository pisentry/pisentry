package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pisentry/pisentry/internal/rules"
)

const rule = `{"schema_version":1,"rules":[{"id":"PACK-TEST","title":"Test","category":"PS04","level":"high","source":"log","match":{"all":[{"field":"log.msg","contains":["evil"]}]}}]}`

func TestSignOutputVerifies(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	key := base64.StdEncoding.EncodeToString(priv.Seed())
	src := filepath.Join(t.TempDir(), "ssh.json")
	if err := os.WriteFile(src, []byte(rule), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "bundle")
	now := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	if err := sign([]string{"-version", "202611150000", "-min-agent", "v0.2.2", "-out", out, src}, key, now); err != nil {
		t.Fatal(err)
	}
	m, err := rules.VerifyDir(out, []ed25519.PublicKey{priv.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	if m.Version != 202611150000 || m.Files[0].Name != "bundle-ssh.json" || !m.Expires.Equal(now.Add(90*24*time.Hour)) {
		t.Fatalf("manifest %+v", m)
	}
	if err := sign([]string{"-version", "1", "-out", out, src}, key, now); err == nil {
		t.Fatal("signed into a non-empty directory")
	}
	if err := sign([]string{"-version", "1", "-out", t.TempDir(), src}, "", now); err == nil {
		t.Fatal("signed without a key")
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte(`{"schema_version":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := sign([]string{"-version", "1", "-out", t.TempDir(), bad}, key, now); err == nil {
		t.Fatal("signed an invalid rule file")
	}
}

func TestKeygen(t *testing.T) {
	out := filepath.Join(t.TempDir(), "key")
	if err := keygen([]string{"-out", out}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rules.ParsePrivateKey(string(b)); err != nil {
		t.Fatal(err)
	}
	if err := keygen([]string{"-out", out}); err == nil {
		t.Fatal("keygen overwrote an existing key")
	}
}
