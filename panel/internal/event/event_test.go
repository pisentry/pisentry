package event

import (
	"strings"
	"testing"
)

const good = `{"id":"e1","schema_version":1,"time":"2026-10-15T05:14:02Z","host":"kubepi",
"category":"PS08","category_name":"Reverse shell","severity":"critical","summary":"Reverse shell: bash",
"rule":{"id":"PS08-DEV-TCP","title":"x"},"something_new":true}`

func TestParseGood(t *testing.T) {
	e, err := Parse([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	if e.ID != "e1" || e.Category != "PS08" || e.Severity != "critical" || e.RuleID != "PS08-DEV-TCP" || e.Host != "kubepi" {
		t.Fatalf("got %+v", e)
	}
	if string(e.Raw) != good {
		t.Fatal("raw JSON not kept as sent")
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string]string{
		"version":  strings.Replace(good, `"schema_version":1`, `"schema_version":9`, 1),
		"id":       strings.Replace(good, `"id":"e1"`, `"id":""`, 1),
		"category": strings.Replace(good, `"PS08"`, `"XX08"`, 1),
		"severity": strings.Replace(good, `"critical"`, `"urgent"`, 1),
		"summary":  strings.Replace(good, `"Reverse shell: bash"`, `""`, 1),
		"time":     strings.Replace(good, `"time":"2026-10-15T05:14:02Z",`, ``, 1),
		"json":     `{"id":`,
		"utf8":     "{\"id\":\"\xff\"}",
		"size":     `{"id":"` + strings.Repeat("a", MaxRaw) + `"}`,
	}
	for name, raw := range cases {
		if _, err := Parse([]byte(raw)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestSeverityRank(t *testing.T) {
	if SeverityRank("critical") <= SeverityRank("high") || SeverityRank("nope") != -1 {
		t.Fatal("bad ranking")
	}
}
