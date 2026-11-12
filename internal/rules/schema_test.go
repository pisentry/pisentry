package rules

import (
	"slices"
	"strings"
	"testing"

	"github.com/pisentry/pisentry/internal/event"
)

func baseRule() Rule {
	return Rule{
		ID: "T-1", Title: "t", Category: event.PrivEsc, Level: event.High, Source: SourceLog,
		Match: MatchSpec{All: []FieldCondition{{Field: "log.msg", Contains: []string{"evil"}}}},
	}
}

func mustCompile(t *testing.T, r Rule) *CompiledRule {
	t.Helper()
	cr, err := CompileRule("t.json", 0, r)
	if err != nil {
		t.Fatal(err)
	}
	return cr
}

func TestCompileRuleRejects(t *testing.T) {
	long := strings.Repeat("a", MaxPatternLen+1)
	manyConds := make([]FieldCondition, MaxConditionsPerRule+1)
	for i := range manyConds {
		manyConds[i] = FieldCondition{Field: "log.msg", Equals: []string{"x"}}
	}
	manyPats := make([]string, MaxPatternsPerRule+1)
	for i := range manyPats {
		manyPats[i] = "p"
	}
	manyEx := make([]Exception, MaxExceptionsPerRule+1)
	for i := range manyEx {
		manyEx[i] = Exception{Users: []string{"x"}}
	}

	cases := []struct {
		name  string
		mut   func(*Rule)
		field string
	}{
		{"no id", func(r *Rule) { r.ID = "" }, `rules[0] field "id"`},
		{"bad id", func(r *Rule) { r.ID = "has space" }, `field "id"`},
		{"long id", func(r *Rule) { r.ID = strings.Repeat("a", MaxIDLen+1) }, `field "id"`},
		{"no title", func(r *Rule) { r.Title = "" }, `field "title"`},
		{"long desc", func(r *Rule) { r.Description = strings.Repeat("a", MaxDescLen+1) }, `field "description"`},
		{"bad status", func(r *Rule) { r.Status = "beta" }, `field "status"`},
		{"no category", func(r *Rule) { r.Category = "" }, `field "category"`},
		{"bad category", func(r *Rule) { r.Category = "XX01" }, `field "category"`},
		{"category not in catalog", func(r *Rule) { r.Category = "PS99" }, `unknown category "PS99"`},
		{"bad source", func(r *Rule) { r.Source = "ebpf" }, `field "source"`},
		{"file source not evaluated", func(r *Rule) { r.Source = "file" }, `must be process or log (got "file")`},
		{"network source not evaluated", func(r *Rule) { r.Source = "network" }, `field "source"`},
		{"k3s source not evaluated", func(r *Rule) { r.Source = "k3s" }, `field "source"`},
		{"bad response", func(r *Rule) { r.Response = "reboot" }, `field "response"`},
		{"long tag", func(r *Rule) { r.Tags = []string{long} }, `field "tags"`},
		{"bad mitre", func(r *Rule) { r.MITRE = []string{"T12"} }, `field "mitre"`},
		{"no conditions", func(r *Rule) { r.Match = MatchSpec{} }, `field "match"`},
		{"too many conditions", func(r *Rule) { r.Match = MatchSpec{Any: manyConds} }, `too many conditions`},
		{"unknown field", func(r *Rule) { r.Match.All[0].Field = "process.env" }, `match.all[0].field`},
		{"field from another source", func(r *Rule) { r.Match.All[0].Field = "process.exe" }, `"process.exe" is not filled for source log rules`},
		{"field no source fills", func(r *Rule) { r.Match.All[0].Field = "file.path" }, `match.all[0].field`},
		{"user.uid is not filled", func(r *Rule) { r.Match.Any = []FieldCondition{{Field: "user.uid", Equals: []string{"0"}}} }, `match.any[0].field`},
		{"no patterns", func(r *Rule) { r.Match.All[0] = FieldCondition{Field: "log.msg"} }, `has no patterns`},
		{"too many patterns", func(r *Rule) { r.Match.All[0].Contains = manyPats }, `max patterns`},
		{"empty literal", func(r *Rule) { r.Match.All[0].Contains = []string{""} }, `empty literal`},
		{"long literal", func(r *Rule) { r.Match.All[0].Contains = []string{long} }, `pattern length`},
		{"empty regex", func(r *Rule) { r.Match.Any = []FieldCondition{{Field: "log.msg", Regex: []string{""}}} }, `empty regex`},
		{"long regex", func(r *Rule) { r.Match.Any = []FieldCondition{{Field: "log.msg", Regex: []string{long}}} }, `regex length`},
		{"bad regex", func(r *Rule) { r.Match.Any = []FieldCondition{{Field: "log.msg", Regex: []string{"(a"}}} }, `invalid regex`},
		{"backreference", func(r *Rule) { r.Match.Any = []FieldCondition{{Field: "log.msg", Regex: []string{`(a)\1`}}} }, `invalid regex`},
		{"too many exceptions", func(r *Rule) { r.Exceptions = manyEx }, `too many exceptions`},
		{"empty exception", func(r *Rule) { r.Exceptions = []Exception{{}} }, `would suppress all`},
		{"exception too many values", func(r *Rule) { r.Exceptions = []Exception{{Users: manyPats}} }, `too many values`},
		{"exception empty value", func(r *Rule) { r.Exceptions = []Exception{{Users: []string{""}}} }, `empty value`},
		{"exception long value", func(r *Rule) { r.Exceptions = []Exception{{Users: []string{long}}} }, `value length`},
		{"exception key from another source", func(r *Rule) { r.Exceptions = []Exception{{Comm: []string{"ansible"}}} }, `exceptions[0].comm": never matches for source log rules`},
		{"exception uids on log", func(r *Rule) { r.Exceptions = []Exception{{UIDs: []int{0}}} }, `exceptions[0].uids`},
		{"exception cidrs", func(r *Rule) { r.Exceptions = []Exception{{CIDRs: []string{"10.0.0.0/8"}}} }, `exceptions[0].cidrs`},
		{"exception paths", func(r *Rule) { r.Exceptions = []Exception{{Paths: []string{"/etc/*"}}} }, `exceptions[0].paths`},
		{"exception container image", func(r *Rule) { r.Exceptions = []Exception{{ContainerImage: []string{"ghcr.io/*"}}} }, `exceptions[0].container_image`},
		{"exception key named even with a valid one", func(r *Rule) { r.Exceptions = []Exception{{Users: []string{"pi"}, Exe: []string{"/bin/sh"}}} }, `exceptions[0].exe`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := baseRule()
			c.mut(&r)
			_, err := CompileRule("t.json", 0, r)
			wantErr(t, err, c.field)
			if !strings.HasPrefix(err.Error(), "t.json: ") {
				t.Errorf("error must name the file: %v", err)
			}
		})
	}
}

func TestCompileRuleNormalizes(t *testing.T) {
	r := baseRule()
	r.Tags = []string{"attack.t1548.003", "attack.privilege_escalation", "ATTACK.T1059"}
	r.MITRE = []string{"T1548.003"}
	cr := mustCompile(t, r)
	if got := strings.Join(cr.Rule.MITRE, ","); got != "T1548.003,T1059" {
		t.Errorf("MITRE from tags = %q", got)
	}
	if cr.Rule.Response != "none" {
		t.Errorf("response = %q, want none", cr.Rule.Response)
	}
}

func TestMatchOperators(t *testing.T) {
	cases := []struct {
		name string
		cond FieldCondition
		val  string
		want bool
	}{
		{"equals", FieldCondition{Equals: []string{"sudo"}}, "sudo", true},
		{"equals is exact", FieldCondition{Equals: []string{"sudo"}}, "sudoedit", false},
		{"contains", FieldCondition{Contains: []string{"tcp://"}}, "stratum+tcp://pool", true},
		{"startswith", FieldCondition{StartsWith: []string{"/tmp/"}}, "/tmp/x", true},
		{"startswith miss", FieldCondition{StartsWith: []string{"/tmp/"}}, "/usr/tmp/x", false},
		{"endswith", FieldCondition{EndsWith: []string{".sh"}}, "/tmp/a.sh", true},
		{"case sensitive", FieldCondition{Contains: []string{"XMRig"}}, "xmrig", false},
		{"case insensitive literal", FieldCondition{Contains: []string{"XMRig"}, CaseInsensitive: true}, "/tmp/XMRIG", true},
		{"regex", FieldCondition{Regex: []string{`^a+b$`}}, "aaab", true},
		{"regex miss", FieldCondition{Regex: []string{`^a+b$`}}, "aaabc", false},
		{"case insensitive regex", FieldCondition{Regex: []string{`setcap`}, CaseInsensitive: true}, "SETCAP", true},
		{"ci regex already flagged", FieldCondition{Regex: []string{`(?i)setcap`}, CaseInsensitive: true}, "SetCap", true},
		{"literal or regex", FieldCondition{Equals: []string{"x"}, Regex: []string{`^y`}}, "yes", true},
		{"empty value", FieldCondition{Contains: []string{"a"}}, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := baseRule()
			c.cond.Field = "log.msg"
			r.Match = MatchSpec{All: []FieldCondition{c.cond}}
			cr := mustCompile(t, r)
			if got := cr.Match(&EvalInput{Source: SourceLog, LogMsg: c.val}); got != c.want {
				t.Errorf("Match(%q) = %v, want %v", c.val, got, c.want)
			}
		})
	}
}

func TestMatchAllAny(t *testing.T) {
	r := baseRule()
	r.Match = MatchSpec{
		All: []FieldCondition{{Field: "log.ident", Equals: []string{"sudo"}}},
		Any: []FieldCondition{
			{Field: "process.cmdline", Contains: []string{"setcap"}},
			{Field: "process.cmdline", Contains: []string{"chattr"}},
		},
	}
	cr := mustCompile(t, r)
	in := func(ident, cmd string) *EvalInput {
		return &EvalInput{Source: SourceLog, LogIdent: ident, Process: event.ProcessEntity{Cmdline: cmd}}
	}
	if !cr.Match(in("sudo", "chattr +i /etc/passwd")) {
		t.Error("all + one of any should match")
	}
	if cr.Match(in("su", "chattr +i /etc/passwd")) {
		t.Error("failing all must not match")
	}
	if cr.Match(in("sudo", "ls")) {
		t.Error("no any condition holding must not match")
	}
	if cr.Match(&EvalInput{Source: SourceProcess, LogIdent: "sudo", Process: event.ProcessEntity{Cmdline: "setcap"}}) {
		t.Error("wrong source must not match")
	}
	// An empty source evaluates every rule, which is what fixtures without a
	// source and `Engine.Eval` callers that do not know the source rely on.
	if !cr.Match(&EvalInput{LogIdent: "sudo", Process: event.ProcessEntity{Cmdline: "setcap"}}) {
		t.Error("empty input source should not filter")
	}
}

func TestExceptions(t *testing.T) {
	uid := func(n int) *int { return &n }
	procRule := func() Rule {
		r := baseRule()
		r.Source = SourceProcess
		r.Match = MatchSpec{All: []FieldCondition{{Field: "process.cmdline", Contains: []string{"site.yml"}}}}
		return r
	}
	procHit := func() *EvalInput {
		return &EvalInput{
			Source:     SourceProcess,
			Process:    event.ProcessEntity{Exe: "/usr/bin/ansible-playbook", Comm: "ansible", Cmdline: "ansible-playbook site.yml", UID: uid(1000)},
			ParentComm: "sshd",
		}
	}
	logHit := func() *EvalInput {
		return &EvalInput{
			Source:  SourceLog,
			LogMsg:  "evil",
			User:    event.UserEntity{Name: "deploy"},
			Process: event.ProcessEntity{Cmdline: "ansible-playbook site.yml"},
		}
	}
	cases := []struct {
		name string
		rule func() Rule
		hit  func() *EvalInput
		ex   Exception
		mut  func(*EvalInput)
		want bool // true = suppressed
	}{
		{"exe", procRule, procHit, Exception{Exe: []string{"/usr/bin/ansible-playbook"}}, nil, true},
		{"exe miss", procRule, procHit, Exception{Exe: []string{"/usr/bin/other"}}, nil, false},
		{"exe prefix", procRule, procHit, Exception{ExePrefix: []string{"/usr/bin/"}}, nil, true},
		{"exe prefix miss", procRule, procHit, Exception{ExePrefix: []string{"/opt/"}}, nil, false},
		{"comm", procRule, procHit, Exception{Comm: []string{"ansible"}}, nil, true},
		{"comm miss", procRule, procHit, Exception{Comm: []string{"bash"}}, nil, false},
		{"parent comm", procRule, procHit, Exception{ParentComm: []string{"sshd"}}, nil, true},
		{"parent comm miss", procRule, procHit, Exception{ParentComm: []string{"cron"}}, nil, false},
		{"process uid", procRule, procHit, Exception{UIDs: []int{1000}}, nil, true},
		{"uid miss", procRule, procHit, Exception{UIDs: []int{0}}, nil, false},
		{"unknown uid never matches", procRule, procHit, Exception{UIDs: []int{0}}, func(in *EvalInput) { in.Process.UID = nil }, false},
		{"process cmdline contains", procRule, procHit, Exception{CmdlineContains: []string{"site.yml"}}, nil, true},
		{"all predicates must hold", procRule, procHit, Exception{Comm: []string{"ansible"}, UIDs: []int{0}}, nil, false},
		{"all predicates hold", procRule, procHit, Exception{Comm: []string{"ansible"}, UIDs: []int{1000}}, nil, true},
		{"user", baseRule, logHit, Exception{Users: []string{"deploy"}}, nil, true},
		{"user miss", baseRule, logHit, Exception{Users: []string{"root"}}, nil, false},
		{"log cmdline contains", baseRule, logHit, Exception{CmdlineContains: []string{"site.yml"}}, nil, true},
		{"log cmdline miss", baseRule, logHit, Exception{CmdlineContains: []string{"other.yml"}}, nil, false},
		{"log user and cmdline", baseRule, logHit, Exception{Users: []string{"deploy"}, CmdlineContains: []string{"other.yml"}}, nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := c.rule()
			r.Exceptions = []Exception{c.ex}
			cr := mustCompile(t, r)
			in := c.hit()
			if c.mut != nil {
				c.mut(in)
			}
			if suppressed := !cr.Match(in); suppressed != c.want {
				t.Errorf("suppressed = %v, want %v", suppressed, c.want)
			}
		})
	}

	// Multiple exceptions are ORed.
	r := baseRule()
	r.Exceptions = []Exception{{Users: []string{"nope"}}, {Users: []string{"deploy"}}}
	if mustCompile(t, r).Match(logHit()) {
		t.Error("second exception should suppress")
	}
}

// Every field a source accepts must be readable from EvalInput, or a rule on
// it would silently never match.
func TestEveryAllowedFieldIsWired(t *testing.T) {
	uid := 7
	in := &EvalInput{
		Process:    event.ProcessEntity{PID: 10, PPID: 1, UID: &uid, Comm: "c", Exe: "/e", Cmdline: "cmd"},
		ParentComm: "pc",
		User:       event.UserEntity{Name: "u"},
		LogIdent:   "sudo",
		LogMsg:     "msg",
	}
	for src, spec := range sources {
		for _, f := range spec.fields {
			if in.Field(f) == "" {
				t.Errorf("source %s allows field %q but EvalInput.Field returns nothing for it", src, f)
			}
		}
	}
	if (&EvalInput{}).Field("process.pid") != "" || (&EvalInput{}).Field("process.ppid") != "" ||
		(&EvalInput{}).Field("process.uid") != "" || (&EvalInput{}).Field("bogus") != "" {
		t.Error("unset numeric fields must read as empty, not \"0\"")
	}
}

// Each source accepts exactly the exception keys that Exception.matches reads
// for it. An accepted key whose input the source never fills would load and
// never suppress, which is what #51 was about.
func TestExceptionKeysAreKnown(t *testing.T) {
	all := Exception{
		Exe: []string{"x"}, ExePrefix: []string{"x"}, Comm: []string{"x"}, ParentComm: []string{"x"},
		UIDs: []int{1}, Users: []string{"x"}, ContainerImage: []string{"x"}, CIDRs: []string{"x"},
		Paths: []string{"x"}, CmdlineContains: []string{"x"},
	}
	known := all.keys()
	if len(known) != 10 {
		t.Fatalf("Exception.keys() = %v, want all 10 keys", known)
	}
	for src, spec := range sources {
		for _, k := range spec.exceptions {
			if !slices.Contains(known, k) {
				t.Errorf("source %s lists unknown exception key %q", src, k)
			}
		}
		for _, k := range []string{"container_image", "cidrs", "paths"} {
			if slices.Contains(spec.exceptions, k) {
				t.Errorf("source %s accepts %q, which no detector fills", src, k)
			}
		}
	}
}

func TestEngineEval(t *testing.T) {
	var nilEng *Engine
	if nilEng.Eval(&EvalInput{}) != nil {
		t.Error("nil engine should match nothing")
	}
	in := &EvalInput{Source: SourceLog, LogIdent: "sudo", Process: event.ProcessEntity{Cmdline: "/usr/sbin/setcap cap_setuid+ep /tmp/python3"}}
	hits := Default().Eval(in)
	if len(hits) != 1 || hits[0].ID != "PS04-SUDO-SETCAP" {
		t.Fatalf("hits = %v", hits)
	}
	in.Source = ""
	if hits := Default().Eval(in); len(hits) != 1 {
		t.Fatalf("empty source should search all rules, got %v", hits)
	}
}

func TestUsesField(t *testing.T) {
	eng, err := NewEngineFromBytes("t.json", bundleJSON(t, map[string]any{
		"id": "WEB-SHELL", "title": "t", "category": "PS08", "level": "high", "source": "process",
		"match": map[string]any{
			"all": []any{map[string]any{"field": "process.comm", "equals": []any{"sh"}}},
			"any": []any{map[string]any{"field": "process.parent_comm", "equals": []any{"nginx"}}},
		},
		"exceptions": []any{map[string]any{"uids": []any{33}}},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !eng.UsesField(SourceProcess, "process.parent_comm") || !eng.UsesField(SourceProcess, "process.comm") {
		t.Error("match condition fields not reported")
	}
	if eng.UsesField(SourceProcess, "process.uid") {
		t.Error("exception-only field reported as a match field")
	}
	if eng.UsesField(SourceLog, "process.comm") {
		t.Error("field reported for a source with no rules")
	}
	var nilEng *Engine
	if nilEng.UsesField(SourceProcess, "process.comm") {
		t.Error("nil engine reported a field")
	}
	// ProcWatch reads uid and parent comm for every process when a rule
	// matches on them; the defaults should not force that cost.
	if Default().UsesField(SourceProcess, "process.parent_comm") || Default().UsesField(SourceProcess, "process.uid") {
		t.Error("default process rules match on parent_comm or uid")
	}
}
