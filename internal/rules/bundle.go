package rules

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// A signed rule bundle is a set of rule files plus a manifest that lists
// their SHA-256 hashes, signed with Ed25519. The same three names are used on
// the download server, in rules.d and in a GitOps ConfigMap:
//
//	bundle.manifest   the manifest (JSON), see Manifest
//	bundle.sig        the detached signature (JSON), see Signature
//	bundle-*.json     the rule files the manifest lists
//
// The loader skips bundle.manifest and bundle.sig because they do not end in
// .json, and loads bundle-*.json like any other rule file.
const (
	ManifestName     = "bundle.manifest"
	SignatureName    = "bundle.sig"
	BundleFilePrefix = "bundle-"

	ManifestSchemaVersion = 1
	MaxManifestSize       = 64 << 10
	MaxSignatureSize      = 4 << 10
)

// signContext is prepended to the manifest before signing, so a signature
// made for something else with the same key can never verify as a bundle.
const signContext = "pisentry-rule-bundle-v1\n"

// trustedKeys are the Ed25519 public keys (base64, 32 bytes) that may sign
// rule bundles. Two slots: the key the release workflow signs with now, and
// the next one, so the signing key can rotate without a breaking release.
// docs/rule-schema.md ("Signed bundles") has the rotation steps.
var trustedKeys = []string{
	// current: none yet, see "One-time setup" in docs/rule-schema.md
	// next:    none yet
}

var (
	ErrUnsigned     = errors.New("bundle is not signed")
	ErrUnknownKey   = errors.New("bundle is signed with a key this build does not trust")
	ErrBadSignature = errors.New("bundle signature does not verify")
	ErrHashMismatch = errors.New("file does not match the manifest")
	ErrExpired      = errors.New("bundle manifest has expired")
	ErrOlderVersion = errors.New("bundle is older than the installed one")
	ErrAgentTooOld  = errors.New("bundle needs a newer pisentry")
)

// Manifest describes one signed bundle.
type Manifest struct {
	SchemaVersion int `json:"schema_version"`
	// Version only goes up. update-patterns refuses a bundle whose version
	// is lower than the installed one, so an old, validly signed bundle
	// cannot be replayed to remove a newer rule.
	Version uint64    `json:"version"`
	Created time.Time `json:"created"`
	// Expires bounds how long a stale bundle can be served: update-patterns
	// refuses an expired manifest even if the version is new to it.
	Expires         time.Time      `json:"expires"`
	MinAgentVersion string         `json:"min_agent_version,omitempty"`
	Files           []ManifestFile `json:"files"`
}

// ManifestFile is one rule file in a bundle.
type ManifestFile struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Signature is the content of bundle.sig. Signature is base64 in JSON.
type Signature struct {
	KeyID     string `json:"key_id"`
	Signature []byte `json:"signature"`
}

var (
	bundleNameRe = regexp.MustCompile(`^bundle-[a-z0-9][a-z0-9._-]{0,63}\.json$`)
	sha256Re     = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// KeyID names a public key: the first 8 bytes of its SHA-256, in hex. It is
// derived from the key, so an ID can never point at the wrong key.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// ParsePublicKey decodes a base64 Ed25519 public key.
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("public key: %w", err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key: %d bytes, want %d", len(b), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(b), nil
}

// ParsePrivateKey decodes a base64 Ed25519 seed (32 bytes), the format
// `pisentry-bundle keygen` writes.
func ParsePrivateKey(s string) (ed25519.PrivateKey, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, errors.New("private key: not valid base64")
	}
	if len(b) != ed25519.SeedSize {
		return nil, fmt.Errorf("private key: %d bytes, want a %d-byte seed", len(b), ed25519.SeedSize)
	}
	return ed25519.NewKeyFromSeed(b), nil
}

// TrustedKeys returns the public keys embedded in this build.
func TrustedKeys() []ed25519.PublicKey {
	keys := make([]ed25519.PublicKey, 0, len(trustedKeys))
	for i, s := range trustedKeys {
		k, err := ParsePublicKey(s)
		if err != nil {
			panic(fmt.Sprintf("embedded bundle key %d: %v", i, err))
		}
		keys = append(keys, k)
	}
	return keys
}

// SignManifest signs manifest bytes and returns the content of bundle.sig.
func SignManifest(manifest []byte, priv ed25519.PrivateKey) ([]byte, error) {
	if _, err := parseManifest(manifest); err != nil {
		return nil, err
	}
	pub := priv.Public().(ed25519.PublicKey)
	sig := Signature{KeyID: KeyID(pub), Signature: ed25519.Sign(priv, signedMessage(manifest))}
	b, err := json.MarshalIndent(sig, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func signedMessage(manifest []byte) []byte {
	return append([]byte(signContext), manifest...)
}

// VerifyManifest checks the signature over manifest with one of keys and only
// then parses and validates the manifest.
func VerifyManifest(manifest, sig []byte, keys []ed25519.PublicKey) (*Manifest, error) {
	if len(bytes.TrimSpace(sig)) == 0 {
		return nil, ErrUnsigned
	}
	if len(sig) > MaxSignatureSize {
		return nil, fmt.Errorf("%s: size %d exceeds limit %d", SignatureName, len(sig), MaxSignatureSize)
	}
	if len(manifest) > MaxManifestSize {
		return nil, fmt.Errorf("%s: size %d exceeds limit %d", ManifestName, len(manifest), MaxManifestSize)
	}
	var s Signature
	if err := strictJSON(sig, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", SignatureName, err)
	}
	if s.KeyID == "" || len(s.Signature) == 0 {
		return nil, ErrUnsigned
	}
	var key ed25519.PublicKey
	for _, k := range keys {
		if KeyID(k) == s.KeyID {
			key = k
			break
		}
	}
	if key == nil {
		return nil, fmt.Errorf("%w (key id %q)", ErrUnknownKey, s.KeyID)
	}
	if !ed25519.Verify(key, signedMessage(manifest), s.Signature) {
		return nil, fmt.Errorf("%w (key id %s)", ErrBadSignature, s.KeyID)
	}
	return parseManifest(manifest)
}

func parseManifest(b []byte) (*Manifest, error) {
	var m Manifest
	if err := strictJSON(b, &m); err != nil {
		return nil, fmt.Errorf("%s: %w", ManifestName, err)
	}
	if err := m.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", ManifestName, err)
	}
	return &m, nil
}

func strictJSON(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("invalid json: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("unexpected trailing data after top-level JSON object")
	}
	return nil
}

func (m *Manifest) validate() error {
	if m.SchemaVersion != ManifestSchemaVersion {
		return fmt.Errorf("field \"schema_version\": got %d, want %d", m.SchemaVersion, ManifestSchemaVersion)
	}
	if m.Version == 0 {
		return errors.New("field \"version\": required")
	}
	if m.Created.IsZero() || m.Expires.IsZero() {
		return errors.New("fields \"created\" and \"expires\": required")
	}
	if !m.Expires.After(m.Created) {
		return errors.New("field \"expires\": must be after \"created\"")
	}
	if m.MinAgentVersion != "" {
		if _, ok := parseSemver(m.MinAgentVersion); !ok {
			return fmt.Errorf("field \"min_agent_version\": %q is not a version like v0.2.2", m.MinAgentVersion)
		}
	}
	if len(m.Files) == 0 {
		return errors.New("field \"files\": bundle lists no files")
	}
	if len(m.Files) > MaxRuleFiles {
		return fmt.Errorf("field \"files\": count %d exceeds limit %d", len(m.Files), MaxRuleFiles)
	}
	seen := map[string]bool{}
	for i, f := range m.Files {
		if !bundleNameRe.MatchString(f.Name) {
			return fmt.Errorf("field \"files[%d].name\": %q must look like bundle-<name>.json", i, f.Name)
		}
		if seen[f.Name] {
			return fmt.Errorf("field \"files[%d].name\": duplicate %q", i, f.Name)
		}
		seen[f.Name] = true
		if !sha256Re.MatchString(f.SHA256) {
			return fmt.Errorf("field \"files[%d].sha256\": want 64 lowercase hex characters", i)
		}
		if f.Size <= 0 || f.Size > MaxFileSize {
			return fmt.Errorf("field \"files[%d].size\": %d outside 1..%d", i, f.Size, MaxFileSize)
		}
	}
	return nil
}

// CheckFile compares b with the manifest entry for name.
func (m *Manifest) CheckFile(name string, b []byte) error {
	for _, f := range m.Files {
		if f.Name != name {
			continue
		}
		sum := sha256.Sum256(b)
		if int64(len(b)) != f.Size || hex.EncodeToString(sum[:]) != f.SHA256 {
			return fmt.Errorf("%s: %w (sha256 %x, size %d)", name, ErrHashMismatch, sum, len(b))
		}
		return nil
	}
	return fmt.Errorf("%s: not listed in the manifest", name)
}

// CheckFresh fails once the manifest has expired.
func (m *Manifest) CheckFresh(now time.Time) error {
	if !m.Expires.After(now) {
		return fmt.Errorf("%w: version %d expired %s", ErrExpired, m.Version, m.Expires.UTC().Format(time.RFC3339))
	}
	return nil
}

// CheckAgent fails when the bundle needs a newer agent than agentVersion. A
// development build ("dev", or anything that is not a version) is not checked.
func (m *Manifest) CheckAgent(agentVersion string) error {
	if m.MinAgentVersion == "" {
		return nil
	}
	have, ok := parseSemver(agentVersion)
	if !ok {
		return nil
	}
	want, _ := parseSemver(m.MinAgentVersion)
	for i := range have {
		if have[i] != want[i] {
			if have[i] < want[i] {
				return fmt.Errorf("%w: version %d needs pisentry %s, this is %s", ErrAgentTooOld, m.Version, m.MinAgentVersion, agentVersion)
			}
			return nil
		}
	}
	return nil
}

// parseSemver reads v1.2.3 or 1.2.3, ignoring any -prerelease or +build
// suffix (git describe output like v0.2.1-4-gabc123 counts as v0.2.1).
func parseSemver(s string) ([3]int, bool) {
	var v [3]int
	s = strings.TrimPrefix(s, "v")
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return v, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return v, false
		}
		v[i] = n
	}
	return v, true
}

// InstalledVersion returns the version in dir/bundle.manifest, or 0 if there
// is none. The signature is not checked: the number is only used as a floor
// for the next update, and a bogus high number can only block updates.
func InstalledVersion(dir string) (uint64, error) {
	b, err := readLimited(filepath.Join(dir, ManifestName), MaxManifestSize)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var m struct {
		Version uint64 `json:"version"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return 0, fmt.Errorf("%s: %w (remove it to reinstall)", filepath.Join(dir, ManifestName), err)
	}
	return m.Version, nil
}

// VerifyDir checks the bundle installed in dir: the signature over
// bundle.manifest and the hash of every file it lists. It returns nil, nil
// when dir holds no bundle. Expiry is not checked here; see CheckFresh.
func VerifyDir(dir string, keys []ed25519.PublicKey) (*Manifest, error) {
	if dir == "" {
		return nil, nil
	}
	mb, err := readLimited(filepath.Join(dir, ManifestName), MaxManifestSize)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	sb, err := readLimited(filepath.Join(dir, SignatureName), MaxSignatureSize)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w: %s is missing", dir, ErrUnsigned, SignatureName)
	}
	if err != nil {
		return nil, err
	}
	m, err := VerifyManifest(mb, sb, keys)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", dir, err)
	}
	for _, f := range m.Files {
		b, err := readLimited(filepath.Join(dir, f.Name), MaxFileSize)
		if err != nil {
			return nil, err
		}
		if err := m.CheckFile(f.Name, b); err != nil {
			return nil, fmt.Errorf("%s: %w", dir, err)
		}
	}
	return m, nil
}

// Load verifies the signed bundle in dir, if there is one, then loads the
// built-in rules plus dir as LoadOrDefault does. A bundle that fails
// verification fails the whole load, like any broken rule file.
func Load(dir string) (*Engine, *Manifest, error) {
	m, err := VerifyDir(dir, TrustedKeys())
	if err != nil {
		return nil, nil, err
	}
	eng, err := LoadOrDefault(dir)
	if err != nil {
		return nil, nil, err
	}
	return eng, m, nil
}

// readLimited reads a regular file (through symlinks) of at most max bytes.
func readLimited(path string, max int64) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", path)
	}
	if fi.Size() > max {
		return nil, fmt.Errorf("%s: size %d exceeds limit %d", path, fi.Size(), max)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%s: size exceeds limit %d", path, max)
	}
	return b, nil
}
