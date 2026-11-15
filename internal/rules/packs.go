package rules

import (
	"embed"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
	"sync"
)

// Rule packs are curated bundles embedded next to default.json and loaded on
// top of it, so the plain binary ships with them. They are on by default and
// rules.disabled_packs turns one off. A pack holds rules only: catalog lists
// stay in default.json so there is one place to read them.
//
//go:embed packs/*.json
var packFS embed.FS

// Pack describes one embedded rule pack.
type Pack struct {
	Name  string
	Rules []*CompiledRule
}

var (
	packsOnce sync.Once
	packList  []Pack

	coreOnce sync.Once
	coreEng  *Engine
)

// Packs returns the embedded rule packs in load order (by file name).
func Packs() []Pack {
	packsOnce.Do(func() {
		files, err := fs.Glob(packFS, "packs/*.json")
		if err != nil {
			panic("rule packs: " + err.Error())
		}
		sort.Strings(files)
		for _, f := range files {
			b, err := packFS.ReadFile(f)
			if err != nil {
				panic("rule pack " + f + ": " + err.Error())
			}
			bundle, crs, err := LoadBytes("embedded/"+f, b)
			if err != nil {
				panic("invalid embedded rule pack: " + err.Error())
			}
			if bundle.Catalog != nil {
				panic("embedded/" + f + ": a rule pack may not carry a catalog")
			}
			packList = append(packList, Pack{Name: strings.TrimSuffix(path.Base(f), ".json"), Rules: crs})
		}
	})
	return packList
}

// PackBytes returns the raw embedded pack file, for the test that keeps
// deploy/rules/packs in step with internal/rules/packs.
func PackBytes(name string) ([]byte, error) {
	return packFS.ReadFile("packs/" + name + ".json")
}

// core is default.json on its own, without packs.
func core() *Engine {
	coreOnce.Do(func() {
		eng, err := NewEngineFromBytes("embedded/default.json", defaultBundleJSON)
		if err != nil {
			panic("invalid embedded default.json: " + err.Error())
		}
		coreEng = eng
	})
	return coreEng
}

// PackState is one embedded pack and whether rules.disabled_packs turns it off.
type PackState struct {
	Name    string
	Rules   int
	Enabled bool
}

// disabledSet validates rules.disabled_packs. An unknown pack name is an
// error, so a typo cannot quietly leave a pack on.
func disabledSet(disabled []string) (map[string]bool, error) {
	known := map[string]bool{}
	var names []string
	for _, p := range Packs() {
		known[p.Name] = true
		names = append(names, p.Name)
	}
	off := map[string]bool{}
	for _, d := range disabled {
		if !known[d] {
			return nil, fmt.Errorf("rules.disabled_packs: unknown pack %q (packs: %s)", d, strings.Join(names, ", "))
		}
		off[d] = true
	}
	return off, nil
}

// PackStates lists the embedded packs with whether each is on under disabled.
func PackStates(disabled []string) ([]PackState, error) {
	off, err := disabledSet(disabled)
	if err != nil {
		return nil, err
	}
	var out []PackState
	for _, p := range Packs() {
		out = append(out, PackState{Name: p.Name, Rules: len(p.Rules), Enabled: !off[p.Name]})
	}
	return out, nil
}

// Base returns default.json plus every embedded pack not named in disabled.
func Base(disabled []string) (*Engine, error) {
	if len(disabled) == 0 {
		return Default(), nil
	}
	off, err := disabledSet(disabled)
	if err != nil {
		return nil, err
	}
	return buildBase(off), nil
}

// checkDisabledOverrides rejects a rules.d rule that reuses the ID of a rule
// in a disabled pack. Loading it would quietly bring back part of a pack the
// operator turned off; a new ID makes keeping that one rule explicit.
func checkDisabledOverrides(eng *Engine, disabled []string) error {
	off, err := disabledSet(disabled)
	if err != nil {
		return err
	}
	for _, p := range Packs() {
		if !off[p.Name] {
			continue
		}
		for _, cr := range p.Rules {
			if _, ok := eng.byID[cr.Rule.ID]; ok {
				return fmt.Errorf("rules.d: rule %s is from disabled pack %s; give it a new id to keep it, or re-enable the pack", cr.Rule.ID, p.Name)
			}
		}
	}
	return nil
}

// buildBase merges default.json and the enabled packs. A rule ID defined
// twice among the built-ins is a build mistake, caught by the tests.
func buildBase(off map[string]bool) *Engine {
	c := core()
	eng := newEmptyEngine()
	mergeCatalog(&eng.catalog, &c.catalog)
	for _, cr := range c.rules {
		eng.addRule(cr)
	}
	for _, p := range Packs() {
		if off[p.Name] {
			continue
		}
		for _, cr := range p.Rules {
			if _, dup := eng.byID[cr.Rule.ID]; dup {
				panic(fmt.Sprintf("embedded rule pack %s: rule %s is already defined by default.json or an earlier pack", p.Name, cr.Rule.ID))
			}
			eng.addRule(cr)
		}
	}
	return eng
}
