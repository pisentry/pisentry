package rules

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var bundleNow = time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)

func testKey(seed byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
}

func pubOf(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }

// testManifest builds a manifest for files, valid at bundleNow.
func testManifest(t *testing.T, version uint64, files map[string][]byte) []byte {
	t.Helper()
	m := Manifest{
		SchemaVersion: ManifestSchemaVersion,
		Version:       version,
		Created:       bundleNow.Add(-time.Hour),
		Expires:       bundleNow.Add(90 * 24 * time.Hour),
	}
	for name, b := range files {
		sum := sha256.Sum256(b)
		m.Files = append(m.Files, ManifestFile{Name: name, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(b))})
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// writeSignedBundle writes files, bundle.manifest and bundle.sig into dir.
func writeSignedBundle(t *testing.T, dir string, key ed25519.PrivateKey, version uint64, files map[string][]byte) {
	t.Helper()
	mb := testManifest(t, version, files)
	sb, err := SignManifest(mb, key)
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range files {
		writeFile(t, dir, name, b)
	}
	writeFile(t, dir, ManifestName, mb)
	writeFile(t, dir, SignatureName, sb)
}

// trustKeys swaps the embedded key list for the test.
func trustKeys(t *testing.T, keys ...ed25519.PrivateKey) {
	t.Helper()
	old := trustedKeys
	trustedKeys = nil
	for _, k := range keys {
		trustedKeys = append(trustedKeys, base64.StdEncoding.EncodeToString(pubOf(k)))
	}
	t.Cleanup(func() { trustedKeys = old })
}

func TestEmbeddedKeysParse(t *testing.T) {
	keys := TrustedKeys()
	if len(keys) > 2 {
		t.Fatalf("%d embedded keys; keep two slots, current and next", len(keys))
	}
	seen := map[string]bool{}
	for _, k := range keys {
		if seen[KeyID(k)] {
			t.Fatalf("duplicate embedded key %s", KeyID(k))
		}
		seen[KeyID(k)] = true
	}
}

func TestVerifyManifest(t *testing.T) {
	cur, next, stranger := testKey(1), testKey(2), testKey(3)
	keys := []ed25519.PublicKey{pubOf(cur), pubOf(next)}
	mb := testManifest(t, 7, map[string][]byte{"bundle-a.json": bundleJSON(t, minimalRule())})

	for _, k := range []ed25519.PrivateKey{cur, next} {
		sb, err := SignManifest(mb, k)
		if err != nil {
			t.Fatal(err)
		}
		m, err := VerifyManifest(mb, sb, keys)
		if err != nil {
			t.Fatalf("key %s: %v", KeyID(pubOf(k)), err)
		}
		if m.Version != 7 || len(m.Files) != 1 {
			t.Fatalf("parsed %+v", m)
		}
	}

	good, _ := SignManifest(mb, cur)
	strange, _ := SignManifest(mb, stranger)
	var forged Signature
	if err := json.Unmarshal(strange, &forged); err != nil {
		t.Fatal(err)
	}
	forged.KeyID = KeyID(pubOf(cur)) // a trusted key ID on a stranger's signature
	forgedSig, _ := json.Marshal(forged)
	tampered := bytes.Replace(mb, []byte(`"version":7`), []byte(`"version":8`), 1)

	cases := []struct {
		name     string
		manifest []byte
		sig      []byte
		want     error
	}{
		{"unsigned", mb, nil, ErrUnsigned},
		{"empty signature", mb, []byte(`{"key_id":"","signature":""}`), ErrUnsigned},
		{"unknown key", mb, strange, ErrUnknownKey},
		{"forged key id", mb, forgedSig, ErrBadSignature},
		{"tampered manifest", tampered, good, ErrBadSignature},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := VerifyManifest(tc.manifest, tc.sig, keys); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
	if _, err := VerifyManifest(mb, good, nil); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("no trusted keys: got %v", err)
	}
	if _, err := VerifyManifest(mb, []byte("not json"), keys); err == nil {
		t.Fatal("garbage signature accepted")
	}
}

// The signature domain-separates bundles: a plain signature over the same
// bytes does not verify.
func TestSignatureNeedsContext(t *testing.T) {
	k := testKey(1)
	mb := testManifest(t, 1, map[string][]byte{"bundle-a.json": bundleJSON(t, minimalRule())})
	raw, _ := json.Marshal(Signature{KeyID: KeyID(pubOf(k)), Signature: ed25519.Sign(k, mb)})
	if _, err := VerifyManifest(mb, raw, []ed25519.PublicKey{pubOf(k)}); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("got %v", err)
	}
}

func TestManifestValidate(t *testing.T) {
	k := testKey(1)
	sum := hex.EncodeToString(make([]byte, 32))
	base := func() Manifest {
		return Manifest{
			SchemaVersion: 1, Version: 1, Created: bundleNow, Expires: bundleNow.Add(time.Hour),
			Files: []ManifestFile{{Name: "bundle-a.json", SHA256: sum, Size: 10}},
		}
	}
	cases := map[string]func(*Manifest){
		"schema version":   func(m *Manifest) { m.SchemaVersion = 2 },
		"zero version":     func(m *Manifest) { m.Version = 0 },
		"no expiry":        func(m *Manifest) { m.Expires = time.Time{} },
		"expires first":    func(m *Manifest) { m.Expires = m.Created.Add(-time.Second) },
		"bad min agent":    func(m *Manifest) { m.MinAgentVersion = "latest" },
		"no files":         func(m *Manifest) { m.Files = nil },
		"path traversal":   func(m *Manifest) { m.Files[0].Name = "bundle-../../etc/passwd.json" },
		"no prefix":        func(m *Manifest) { m.Files[0].Name = "a.json" },
		"not json":         func(m *Manifest) { m.Files[0].Name = "bundle-a.sh" },
		"uppercase sha":    func(m *Manifest) { m.Files[0].SHA256 = "AB" + sum[2:] },
		"short sha":        func(m *Manifest) { m.Files[0].SHA256 = sum[:10] },
		"zero size":        func(m *Manifest) { m.Files[0].Size = 0 },
		"oversize":         func(m *Manifest) { m.Files[0].Size = MaxFileSize + 1 },
		"duplicate name":   func(m *Manifest) { m.Files = append(m.Files, m.Files[0]) },
		"too many entries": func(m *Manifest) { m.Files = make([]ManifestFile, MaxRuleFiles+1) },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			m := base()
			mut(&m)
			mb, _ := json.Marshal(m)
			if _, err := SignManifest(mb, k); err == nil {
				t.Fatal("invalid manifest signed")
			}
		})
	}
	mb, _ := json.Marshal(base())
	withExtra := append(bytes.TrimSuffix(mb, []byte("}")), []byte(`,"extra":1}`)...)
	if _, err := SignManifest(withExtra, k); err == nil {
		t.Fatal("unknown manifest field accepted")
	}
}

func TestManifestChecks(t *testing.T) {
	b := bundleJSON(t, minimalRule())
	m, err := parseManifest(testManifest(t, 3, map[string][]byte{"bundle-a.json": b}))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.CheckFile("bundle-a.json", b); err != nil {
		t.Fatal(err)
	}
	if err := m.CheckFile("bundle-a.json", append(b, ' ')); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("tampered file: %v", err)
	}
	if err := m.CheckFile("bundle-b.json", b); err == nil {
		t.Fatal("unlisted file accepted")
	}
	if err := m.CheckFresh(bundleNow); err != nil {
		t.Fatal(err)
	}
	if err := m.CheckFresh(m.Expires); !errors.Is(err, ErrExpired) {
		t.Fatalf("at expiry: %v", err)
	}

	m.MinAgentVersion = "v0.2.2"
	for v, ok := range map[string]bool{
		"v0.2.2": true, "0.2.2": true, "v0.3.0": true, "v1.0.0": true, "v0.2.10": true,
		"v0.2.1": false, "v0.1.9": false, "v0.2.1-4-gabc123": false,
		"dev": true, "": true, // development builds are not checked
	} {
		err := m.CheckAgent(v)
		if ok != (err == nil) {
			t.Errorf("agent %q: %v", v, err)
		}
		if err != nil && !errors.Is(err, ErrAgentTooOld) {
			t.Errorf("agent %q: wrong error %v", v, err)
		}
	}
}

func TestVerifyDir(t *testing.T) {
	k := testKey(1)
	keys := []ed25519.PublicKey{pubOf(k)}
	files := map[string][]byte{"bundle-a.json": bundleJSON(t, minimalRule())}

	if m, err := VerifyDir(t.TempDir(), keys); m != nil || err != nil {
		t.Fatalf("no bundle: %v %v", m, err)
	}
	if m, err := VerifyDir(filepath.Join(t.TempDir(), "missing"), keys); m != nil || err != nil {
		t.Fatalf("missing dir: %v %v", m, err)
	}

	dir := t.TempDir()
	writeSignedBundle(t, dir, k, 4, files)
	m, err := VerifyDir(dir, keys)
	if err != nil || m.Version != 4 {
		t.Fatalf("good bundle: %v %v", m, err)
	}
	if v, err := InstalledVersion(dir); err != nil || v != 4 {
		t.Fatalf("installed version %d %v", v, err)
	}

	writeFile(t, dir, "bundle-a.json", bundleJSON(t, evilRule("TEST-OTHER")))
	if _, err := VerifyDir(dir, keys); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("tampered file: %v", err)
	}
	os.Remove(filepath.Join(dir, "bundle-a.json"))
	if _, err := VerifyDir(dir, keys); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file: %v", err)
	}

	dir = t.TempDir()
	writeSignedBundle(t, dir, k, 4, files)
	os.Remove(filepath.Join(dir, SignatureName))
	if _, err := VerifyDir(dir, keys); !errors.Is(err, ErrUnsigned) {
		t.Fatalf("missing signature: %v", err)
	}
}

func TestInstalledVersionCorrupt(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ManifestName, []byte("{"))
	if _, err := InstalledVersion(dir); err == nil {
		t.Fatal("corrupt manifest gave a version")
	}
	if v, err := InstalledVersion(t.TempDir()); v != 0 || err != nil {
		t.Fatalf("empty dir: %d %v", v, err)
	}
}

// The agent verifies an installed bundle on every load. A tampered bundle
// file is rejected like any broken rule file: the previous set stays.
func TestLiveVerifiesBundle(t *testing.T) {
	k := testKey(1)
	trustKeys(t, k)
	dir := t.TempDir()
	writeSignedBundle(t, dir, k, 9, map[string][]byte{"bundle-a.json": bundleJSON(t, evilRule("TEST-BUNDLE"))})

	l := NewLive(dir, Default())
	eng, err := l.Reload()
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule(eng, "TEST-BUNDLE") || l.Bundle() == nil || l.Bundle().Version != 9 {
		t.Fatalf("bundle not loaded: bundle=%+v", l.Bundle())
	}

	writeFile(t, dir, "bundle-a.json", bundleJSON(t, evilRule("TEST-SWAPPED")))
	eng, err = l.Reload()
	if !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("tampered bundle: %v", err)
	}
	if !hasRule(eng, "TEST-BUNDLE") || hasRule(eng, "TEST-SWAPPED") || l.Bundle().Version != 9 {
		t.Fatal("tampered bundle replaced the active set")
	}

	trustKeys(t) // a build that does not trust the signer
	writeSignedBundle(t, dir, k, 9, map[string][]byte{"bundle-a.json": bundleJSON(t, evilRule("TEST-BUNDLE"))})
	if _, err := l.Reload(); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("untrusted signer: %v", err)
	}
}

// Re-signing the manifest alone is a change the watcher must see.
func TestFingerprintCoversManifest(t *testing.T) {
	k := testKey(1)
	dir := t.TempDir()
	files := map[string][]byte{"bundle-a.json": bundleJSON(t, minimalRule())}
	writeSignedBundle(t, dir, k, 1, files)
	before, _ := Fingerprint(dir)
	writeSignedBundle(t, dir, k, 2, files)
	after, _ := Fingerprint(dir)
	if before == after {
		t.Fatal("fingerprint ignores bundle.manifest")
	}
}

func hasRule(e *Engine, id string) bool {
	_, ok := e.RuleByID(id)
	return ok
}
