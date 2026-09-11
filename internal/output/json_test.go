package output

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/pranavrav09/RuntimeLens/internal/events"
)

func TestWriteAlert(t *testing.T) {
	var buf bytes.Buffer
	writer := NewJSONWriter(&buf)

	alert := events.Alert{
		Type:      "alert",
		RuleID:    "unauthorized_connection",
		Severity:  "medium",
		EventType: events.TypeConnect,
		Message:   "connection to unauthorized or suspicious destination",
		Timestamp: time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC),
		PID:       1234,
		UID:       1000,
		Process:   "nc",
		DestIP:    "127.0.0.1",
		DestPort:  4444,
	}

	if err := writer.WriteAlert(alert); err != nil {
		t.Fatalf("write alert: %v", err)
	}

	var got events.Alert
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("decode alert: %v", err)
	}

	if got.RuleID != alert.RuleID || got.DestPort != alert.DestPort {
		t.Fatalf("unexpected alert: %+v", got)
	}
}

func TestWriteEventIncludesJobScope(t *testing.T) {
	var buffer bytes.Buffer
	writer := NewJSONWriter(&buffer)
	event := events.Event{
		Type: events.TypeExec, Timestamp: time.Unix(1, 0).UTC(), PID: 7,
		UID: 65534, CgroupID: 1234, Job: "secureguard-42", Process: "payload",
	}
	if err := writer.WriteEvent(event); err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(buffer.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["job"] != "secureguard-42" || decoded["cgroup_id"] != float64(1234) {
		t.Fatalf("scope fields missing: %#v", decoded)
	}
}
