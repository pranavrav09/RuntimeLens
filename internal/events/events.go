package events

import "time"

type Type string

const (
	TypeExec    Type = "exec"
	TypeFile    Type = "file"
	TypeConnect Type = "connect"
)

type Event struct {
	RecordType        string    `json:"type"`
	Type              Type      `json:"event_type"`
	Timestamp         time.Time `json:"ts"`
	KernelTimestampNS uint64    `json:"kernel_ts_ns,omitempty"`
	PID               uint32    `json:"pid"`
	TID               uint32    `json:"tid,omitempty"`
	UID               uint32    `json:"uid"`
	CgroupID          uint64    `json:"cgroup_id"`
	Job               string    `json:"job,omitempty"`
	Process           string    `json:"process"`
	Path              string    `json:"path,omitempty"`
	Args              []string  `json:"argv,omitempty"`
	Flags             uint64    `json:"flags,omitempty"`
	Family            string    `json:"family,omitempty"`
	DestIP            string    `json:"dest_ip,omitempty"`
	DestPort          uint16    `json:"dest_port,omitempty"`
}

type Alert struct {
	Type      string    `json:"type"`
	RuleID    string    `json:"rule_id"`
	Severity  string    `json:"severity"`
	EventType Type      `json:"event_type"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"ts"`
	PID       uint32    `json:"pid"`
	UID       uint32    `json:"uid"`
	CgroupID  uint64    `json:"cgroup_id"`
	Job       string    `json:"job,omitempty"`
	Process   string    `json:"process"`
	Path      string    `json:"path,omitempty"`
	Args      []string  `json:"argv,omitempty"`
	DestIP    string    `json:"dest_ip,omitempty"`
	DestPort  uint16    `json:"dest_port,omitempty"`
}
