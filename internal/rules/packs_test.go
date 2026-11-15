package rules

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The rule packs (#15) promise at least 75 built-in rules, each with a MITRE
// technique. Fixtures for every rule are enforced by TestDefaultRuleFixtures.
func TestBuiltinRuleCountAndMITRE(t *testing.T) {
	eng := Default()
	if n := len(eng.Rules()); n < 75 {
		t.Errorf("built-in rules: %d, want at least 75", n)
	}
	for _, cr := range eng.Rules() {
		if len(cr.Rule.MITRE) == 0 {
			t.Errorf("%s: no MITRE technique", cr.Rule.ID)
		}
	}
}

func TestPacksLoad(t *testing.T) {
	packs := Packs()
	if len(packs) == 0 {
		t.Fatal("no embedded rule packs")
	}
	inPack := map[string]string{}
	for _, p := range packs {
		if len(p.Rules) == 0 {
			t.Errorf("pack %s has no rules", p.Name)
		}
		for _, cr := range p.Rules {
			if prev, dup := inPack[cr.Rule.ID]; dup {
				t.Errorf("rule %s is in packs %s and %s", cr.Rule.ID, prev, p.Name)
			}
			inPack[cr.Rule.ID] = p.Name
			if _, clash := core().RuleByID(cr.Rule.ID); clash {
				t.Errorf("rule %s in pack %s is also in default.json", cr.Rule.ID, p.Name)
			}
		}
	}
	if got, want := len(Default().Rules()), len(core().Rules())+len(inPack); got != want {
		t.Errorf("Default has %d rules, want default.json plus packs = %d", got, want)
	}
}

// deploy/rules/packs is the copy operators read; it must match what the
// binary embeds, file for file.
func TestDeployPacksMatchEmbedded(t *testing.T) {
	dir := filepath.Join("..", "..", "deploy", "rules", "packs")
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != len(Packs()) {
		t.Errorf("deploy/rules/packs has %d files, binary embeds %d packs", len(files), len(Packs()))
	}
	for _, p := range Packs() {
		want, err := PackBytes(p.Name)
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join(dir, p.Name+".json"))
		if err != nil {
			t.Errorf("pack %s: %v", p.Name, err)
			continue
		}
		if !bytes.Equal(got, want) {
			t.Errorf("deploy/rules/packs/%s.json differs from internal/rules/packs/%s.json; copy one over the other", p.Name, p.Name)
		}
	}
}

func TestDisabledPacks(t *testing.T) {
	victim := Packs()[0]
	eng, err := Base([]string{victim.Name})
	if err != nil {
		t.Fatal(err)
	}
	for _, cr := range victim.Rules {
		if _, ok := eng.RuleByID(cr.Rule.ID); ok {
			t.Errorf("pack %s disabled but rule %s still loaded", victim.Name, cr.Rule.ID)
		}
	}
	if got, want := len(eng.Rules()), len(Default().Rules())-len(victim.Rules); got != want {
		t.Errorf("got %d rules with %s off, want %d", got, victim.Name, want)
	}
	if eng.Catalog().ShellNames == nil {
		t.Error("catalog lost when a pack is disabled")
	}

	if _, err := Base([]string{"no-such-pack"}); err == nil || !strings.Contains(err.Error(), "no-such-pack") {
		t.Errorf("unknown pack: %v", err)
	}
	if _, err := LoadOrDefault(t.TempDir(), []string{"no-such-pack"}); err == nil {
		t.Error("LoadOrDefault accepted an unknown pack name")
	}

	// rules.d still overlays on top of the reduced set.
	dir := t.TempDir()
	writeFile(t, dir, "local.json", []byte(`{"schema_version":1,"rules":[{"id":"LOCAL-ONE","title":"t","category":"PS04","source":"log","match":{"all":[{"field":"log.ident","equals":["sudo"]}]}}]}`))
	eng, err = LoadOrDefault(dir, []string{victim.Name})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := eng.RuleByID("LOCAL-ONE"); !ok {
		t.Error("rules.d rule missing when a pack is disabled")
	}
	if _, ok := eng.RuleByID(victim.Rules[0].Rule.ID); ok {
		t.Error("disabled pack came back after a rules.d overlay")
	}
}
