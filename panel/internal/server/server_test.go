package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pisentry/pisentry/panel/internal/store"
)

type fixture struct {
	srv   *httptest.Server
	tok   string
	admin string
	now   time.Time
}

func setup(t *testing.T) *fixture {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "panel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	tok, err := st.AddHost(ctx, "pi-a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddHost(ctx, "pi-b"); err != nil {
		t.Fatal(err)
	}
	admin, _ := st.AdminToken(ctx)
	f := &fixture{tok: tok, admin: admin, now: time.Now().UTC().Truncate(time.Second)}
	s := &Server{Store: st, QuietAfter: 3 * time.Minute, Now: func() time.Time { return f.now }}
	f.srv = httptest.NewServer(s.Handler())
	t.Cleanup(f.srv.Close)
	return f
}

func evJSON(id, cat, sev string, at time.Time) string {
	return fmt.Sprintf(`{"id":%q,"schema_version":1,"time":%q,"host":"pi-a","category":%q,"severity":%q,"summary":"x"}`,
		id, at.Format(time.RFC3339), cat, sev)
}

func (f *fixture) do(t *testing.T, method, path, tok, body string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(method, f.srv.URL+path, strings.NewReader(body))
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestIngestAuth(t *testing.T) {
	f := setup(t)
	body := evJSON("1", "PS08", "critical", f.now)
	for _, tok := range []string{"", "psp_wrong", f.admin} {
		if code, _ := f.do(t, "POST", "/ingest", tok, body); code != http.StatusUnauthorized {
			t.Errorf("token %q: %d", tok, code)
		}
	}
}

func TestIngestFormats(t *testing.T) {
	f := setup(t)
	arr := "[" + evJSON("1", "PS08", "critical", f.now) + "," + evJSON("2", "PS01", "low", f.now) + "]"
	code, body := f.do(t, "POST", "/ingest", f.tok, arr)
	if code != 200 || !strings.Contains(body, `"added":2`) {
		t.Fatalf("array: %d %s", code, body)
	}
	nd := evJSON("2", "PS01", "low", f.now) + "\n\n" + evJSON("3", "PS04", "high", f.now) + "\n"
	code, body = f.do(t, "POST", "/ingest", f.tok, nd)
	if code != 200 || !strings.Contains(body, `"added":1`) {
		t.Fatalf("ndjson with a retry: %d %s", code, body)
	}
	if code, _ := f.do(t, "POST", "/ingest", f.tok, ""); code != 200 {
		t.Fatalf("empty heartbeat: %d", code)
	}
}

func TestIngestRejectsWholeBatch(t *testing.T) {
	f := setup(t)
	bad := "[" + evJSON("1", "PS08", "critical", f.now) + `,{"id":"2","schema_version":1}]`
	code, body := f.do(t, "POST", "/ingest", f.tok, bad)
	if code != 400 || !strings.Contains(body, `"index":1`) {
		t.Fatalf("%d %s", code, body)
	}
	_, list := f.do(t, "GET", "/api/events", f.admin, "")
	if list != "[]\n" {
		t.Fatalf("partial batch stored: %s", list)
	}
	var many strings.Builder
	for i := range maxEvents + 1 {
		many.WriteString(evJSON(fmt.Sprint(i), "PS01", "low", f.now) + "\n")
	}
	if code, _ := f.do(t, "POST", "/ingest", f.tok, many.String()); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("too many events: %d", code)
	}
}

func TestAPI(t *testing.T) {
	f := setup(t)
	f.do(t, "POST", "/ingest", f.tok, evJSON("1", "PS08", "critical", f.now.Add(-time.Minute))+"\n"+evJSON("2", "PS01", "low", f.now))

	if code, _ := f.do(t, "GET", "/api/hosts", "", ""); code != http.StatusUnauthorized {
		t.Fatalf("api without admin token: %d", code)
	}
	if code, _ := f.do(t, "GET", "/api/hosts", f.tok, ""); code != http.StatusUnauthorized {
		t.Fatalf("api with a host token: %d", code)
	}

	_, body := f.do(t, "GET", "/api/hosts", f.admin, "")
	var hosts []hostView
	if err := json.Unmarshal([]byte(body), &hosts); err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 2 || hosts[0].Status != "ok" || hosts[0].Events24h != 2 || hosts[1].Status != "waiting" {
		t.Fatalf("hosts: %s", body)
	}
	f.now = f.now.Add(10 * time.Minute)
	_, body = f.do(t, "GET", "/api/hosts", f.admin, "")
	if !strings.Contains(body, `"status":"quiet"`) {
		t.Fatalf("host should be quiet: %s", body)
	}

	_, body = f.do(t, "GET", "/api/events?severity=high", f.admin, "")
	if !strings.Contains(body, `"id":"1"`) || strings.Contains(body, `"id":"2"`) {
		t.Fatalf("severity filter: %s", body)
	}
	if code, _ := f.do(t, "GET", "/api/events?since=forever", f.admin, ""); code != 400 {
		t.Fatalf("bad since: %d", code)
	}
	if code, body := f.do(t, "GET", "/api/events/pi-a/1", f.admin, ""); code != 200 || !strings.Contains(body, `"PS08"`) {
		t.Fatalf("raw: %d %s", code, body)
	}
	if code, _ := f.do(t, "GET", "/api/events/pi-a/nope", f.admin, ""); code != 404 {
		t.Fatalf("missing raw: %d", code)
	}
	_, body = f.do(t, "GET", "/api/top10", f.admin, "")
	if !strings.Contains(body, `"category":"PS08"`) {
		t.Fatalf("top10: %s", body)
	}
	if _, body = f.do(t, "GET", "/api/top10?host=pi-b", f.admin, ""); strings.TrimSpace(body) != "[]" {
		t.Fatalf("top10 for a host with no events: %s", body)
	}
}

func TestCheckListen(t *testing.T) {
	for addr, ok := range map[string]bool{
		"127.0.0.1:8443": true, "[::1]:8443": true, "localhost:8443": true,
		"0.0.0.0:8443": false, ":8443": false, "192.168.1.5:8443": false, "nonsense": false,
	} {
		if err := CheckListen(addr, false); (err == nil) != ok {
			t.Errorf("%s: %v", addr, err)
		}
	}
	if err := CheckListen(":8443", true); err != nil {
		t.Fatal(err)
	}
}
