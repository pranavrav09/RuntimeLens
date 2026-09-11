package collector

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/pranavrav09/RuntimeLens/internal/events"
)

func TestDecodeConnectEvent(t *testing.T) {
	raw := runtimeLensEvent{
		Type:      bpfEventConnect,
		Pid:       42,
		Tid:       43,
		Uid:       1000,
		CgroupId:  9876,
		Family:    2,
		DestPort:  4444,
		DestAddr4: 0x0100007f,
	}
	copy(raw.Comm[:], "nc")
	var sample bytes.Buffer
	if err := binary.Write(&sample, binary.LittleEndian, raw); err != nil {
		t.Fatal(err)
	}
	event, err := decodeEvent(sample.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if event.Type != events.TypeConnect || event.CgroupID != 9876 || event.DestIP != "127.0.0.1" {
		t.Fatalf("unexpected event: %#v", event)
	}
}

func TestDecodeRejectsUnknownEvent(t *testing.T) {
	raw := runtimeLensEvent{Type: 99}
	var sample bytes.Buffer
	if err := binary.Write(&sample, binary.LittleEndian, raw); err != nil {
		t.Fatal(err)
	}
	if _, err := decodeEvent(sample.Bytes()); err == nil {
		t.Fatal("expected unknown event error")
	}
}
