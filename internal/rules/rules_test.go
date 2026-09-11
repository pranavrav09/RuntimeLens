package rules

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pranavrav09/RuntimeLens/internal/events"
)

func TestLoadFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.yaml")
	data := []byte(`
rules:
  - id: sensitive_file_access
    severity: high
    event: file
    match:
      path_globs:
        - /etc/shadow
`)

	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write rules: %v", err)
	}

	engine, err := LoadFile(path)
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	if len(engine.rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(engine.rules))
	}
}

func TestSensitiveFileAccess(t *testing.T) {
	engine := newTestEngine(t)
	alerts := engine.Evaluate(events.Event{
		Type:      events.TypeFile,
		Timestamp: time.Now().UTC(),
		PID:       100,
		UID:       0,
		Process:   "cat",
		Path:      "/etc/shadow",
	})

	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].RuleID != "sensitive_file_access" {
		t.Fatalf("unexpected rule id %q", alerts[0].RuleID)
	}
}

func TestUnauthorizedConnection(t *testing.T) {
	engine := newTestEngine(t)
	alerts := engine.Evaluate(events.Event{
		Type:      events.TypeConnect,
		Timestamp: time.Now().UTC(),
		PID:       101,
		UID:       1000,
		Process:   "nc",
		DestIP:    "127.0.0.1",
		DestPort:  4444,
	})

	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].RuleID != "unauthorized_connection" {
		t.Fatalf("unexpected rule id %q", alerts[0].RuleID)
	}
}

func TestReverseShellCorrelation(t *testing.T) {
	engine := newTestEngine(t)
	now := time.Now().UTC()

	firstAlerts := engine.Evaluate(events.Event{
		Type:      events.TypeExec,
		Timestamp: now,
		PID:       102,
		UID:       1000,
		Process:   "bash",
		Path:      "/usr/bin/bash",
		Args:      []string{"bash", "-i"},
	})
	if len(firstAlerts) != 0 {
		t.Fatalf("expected no alert before connection, got %d", len(firstAlerts))
	}

	alerts := engine.Evaluate(events.Event{
		Type:      events.TypeConnect,
		Timestamp: now.Add(time.Second),
		PID:       102,
		UID:       1000,
		Process:   "bash",
		DestIP:    "127.0.0.1",
		DestPort:  4444,
	})

	if len(alerts) != 2 {
		t.Fatalf("expected unauthorized connection and reverse shell alerts, got %d", len(alerts))
	}

	var found bool
	for _, alert := range alerts {
		if alert.RuleID == "reverse_shell_bash" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected reverse shell correlation alert")
	}
}

func TestCorrelationAcrossProcessesInSameJob(t *testing.T) {
	engine := correlationEngine(t)
	now := time.Now().UTC()
	engine.Evaluate(events.Event{
		Type: events.TypeExec, Timestamp: now, PID: 201, CgroupID: 9001,
		Path: "/bin/bash", Args: []string{"bash", "-i"},
	})
	alerts := engine.Evaluate(events.Event{
		Type: events.TypeConnect, Timestamp: now.Add(time.Second), PID: 202,
		CgroupID: 9001, Job: "secureguard-42", DestIP: "10.0.0.8", DestPort: 4444,
	})
	if len(alerts) != 1 {
		t.Fatalf("expected cross-process job correlation, got %d alerts", len(alerts))
	}
	if alerts[0].Job != "secureguard-42" || alerts[0].CgroupID != 9001 {
		t.Fatalf("alert lost job identity: %#v", alerts[0])
	}
}

func TestCorrelationDoesNotCrossJobs(t *testing.T) {
	engine := correlationEngine(t)
	now := time.Now().UTC()
	engine.Evaluate(events.Event{
		Type: events.TypeExec, Timestamp: now, PID: 301, CgroupID: 7001,
		Path: "/bin/bash", Args: []string{"bash", "-i"},
	})
	alerts := engine.Evaluate(events.Event{
		Type: events.TypeConnect, Timestamp: now.Add(time.Second), PID: 302,
		CgroupID: 7002, DestIP: "10.0.0.8", DestPort: 4444,
	})
	if len(alerts) != 0 {
		t.Fatalf("events from different jobs correlated: %#v", alerts)
	}
}

func TestRejectsDuplicateRuleIDs(t *testing.T) {
	_, err := NewEngine(Config{Rules: []Rule{{ID: "duplicate", Event: "exec"}, {ID: "duplicate", Event: "file"}}})
	if err == nil {
		t.Fatal("expected duplicate rule error")
	}
}

func TestRejectsIncompleteCorrelation(t *testing.T) {
	_, err := NewEngine(Config{Rules: []Rule{{ID: "unsafe", Event: "correlation"}}})
	if err == nil {
		t.Fatal("expected incomplete correlation error")
	}
}

func correlationEngine(t *testing.T) *Engine {
	t.Helper()
	engine, err := NewEngine(Config{Rules: []Rule{{
		ID: "reverse-shell", Event: "correlation", Window: "5s",
		Match: Match{ExecArgvContains: []string{"bash", "-i"}, ConnectPorts: []uint16{4444}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func newTestEngine(t *testing.T) *Engine {
	t.Helper()

	engine, err := NewEngine(Config{Rules: []Rule{
		{
			ID:       "sensitive_file_access",
			Severity: "high",
			Event:    "file",
			Match: Match{
				PathGlobs: []string{"/etc/shadow", "/root/.ssh/*"},
			},
		},
		{
			ID:       "unauthorized_connection",
			Severity: "medium",
			Event:    "connect",
			Match: Match{
				DestPorts: []uint16{4444, 1337, 31337},
			},
		},
		{
			ID:       "reverse_shell_bash",
			Severity: "high",
			Event:    "correlation",
			Window:   "10s",
			Match: Match{
				ExecArgvContains: []string{"bash", "-i"},
				ConnectPorts:     []uint16{4444, 1337, 31337},
			},
		},
	}})
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}

	return engine
}
