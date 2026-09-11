package collector

//go:generate sh -c "go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel -type event -type settings_value runtimeLens ../../bpf/runtimelens.bpf.c -- -I../../bpf -I/usr/include"

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/pranavrav09/RuntimeLens/internal/events"
)

const (
	bpfEventExec    = 1
	bpfEventFile    = 2
	bpfEventConnect = 3
)

type Collector struct {
	objects  runtimeLensObjects
	links    []link.Link
	reader   *ringbuf.Reader
	warnings []string
	jobs     map[uint64]string
}

type Target struct {
	CgroupID uint64
	Job      string
}

type Options struct {
	Targets []Target
}

func New(options Options) (*Collector, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock limit: %w", err)
	}

	collector := &Collector{jobs: make(map[uint64]string)}
	if err := loadRuntimeLensObjects(&collector.objects, nil); err != nil {
		return nil, fmt.Errorf("load eBPF objects: %w", err)
	}
	if err := collector.configureTargets(options.Targets); err != nil {
		collector.Close()
		return nil, err
	}

	if err := collector.attach(); err != nil {
		collector.Close()
		return nil, err
	}

	reader, err := ringbuf.NewReader(collector.objects.Events)
	if err != nil {
		collector.Close()
		return nil, fmt.Errorf("open ring buffer: %w", err)
	}
	collector.reader = reader

	return collector, nil
}

func (c *Collector) configureTargets(targets []Target) error {
	if len(targets) == 0 {
		return nil
	}

	for _, target := range targets {
		if target.CgroupID == 0 {
			return fmt.Errorf("target cgroup id must not be zero")
		}
		value := uint8(1)
		if err := c.objects.TargetCgroups.Update(target.CgroupID, value, ebpf.UpdateNoExist); err != nil {
			return fmt.Errorf("register cgroup %d: %w", target.CgroupID, err)
		}
		c.jobs[target.CgroupID] = target.Job
	}

	key := uint32(0)
	settings := runtimeLensSettingsValue{FilterEnabled: 1}
	if err := c.objects.Settings.Update(key, settings, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("enable cgroup filter: %w", err)
	}
	return nil
}

func (c *Collector) Warnings() []string {
	return append([]string(nil), c.warnings...)
}

func (c *Collector) Events(ctx context.Context) (<-chan events.Event, <-chan error) {
	eventCh := make(chan events.Event, 128)
	errCh := make(chan error, 1)

	go func() {
		defer close(eventCh)
		defer close(errCh)

		go func() {
			<-ctx.Done()
			if c.reader != nil {
				_ = c.reader.Close()
			}
		}()

		for {
			record, err := c.reader.Read()
			if err != nil {
				if ctx.Err() != nil || errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				errCh <- fmt.Errorf("read ring buffer: %w", err)
				return
			}

			event, err := decodeEvent(record.RawSample)
			if err != nil {
				errCh <- err
				return
			}
			event.Job = c.jobs[event.CgroupID]

			select {
			case eventCh <- event:
			case <-ctx.Done():
				return
			}
		}
	}()

	return eventCh, errCh
}

func (c *Collector) Close() error {
	var errs []error

	if c.reader != nil {
		if err := c.reader.Close(); err != nil && !errors.Is(err, ringbuf.ErrClosed) {
			errs = append(errs, err)
		}
	}

	for _, attached := range c.links {
		if err := attached.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if err := c.objects.Close(); err != nil {
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

func (c *Collector) attach() error {
	required := []struct {
		category string
		name     string
		program  *ebpf.Program
	}{
		{category: "syscalls", name: "sys_enter_execve", program: c.objects.TraceExecve},
		{category: "syscalls", name: "sys_enter_openat", program: c.objects.TraceOpenat},
		{category: "syscalls", name: "sys_enter_connect", program: c.objects.TraceConnect},
	}

	for _, target := range required {
		attached, err := link.Tracepoint(target.category, target.name, target.program, nil)
		if err != nil {
			return fmt.Errorf("attach tracepoint %s/%s: %w", target.category, target.name, err)
		}
		c.links = append(c.links, attached)
	}

	attached, err := link.Tracepoint("syscalls", "sys_enter_openat2", c.objects.TraceOpenat2, nil)
	if err != nil {
		c.warnings = append(c.warnings, fmt.Sprintf("optional tracepoint syscalls/sys_enter_openat2 unavailable: %v", err))
		return nil
	}
	c.links = append(c.links, attached)

	return nil
}

func decodeEvent(sample []byte) (events.Event, error) {
	var raw runtimeLensEvent
	if err := binary.Read(bytes.NewReader(sample), binary.LittleEndian, &raw); err != nil {
		return events.Event{}, fmt.Errorf("decode event: %w", err)
	}

	event := events.Event{
		RecordType:        "event",
		Timestamp:         time.Now().UTC(),
		KernelTimestampNS: raw.TsNs,
		PID:               raw.Pid,
		TID:               raw.Tid,
		UID:               raw.Uid,
		CgroupID:          raw.CgroupId,
		Process:           cString(raw.Comm[:]),
		Path:              cString(raw.Path[:]),
		Flags:             raw.Flags,
	}

	for _, arg := range raw.Argv {
		value := cString(arg[:])
		if value != "" {
			event.Args = append(event.Args, value)
		}
	}

	switch raw.Type {
	case bpfEventExec:
		event.Type = events.TypeExec
	case bpfEventFile:
		event.Type = events.TypeFile
	case bpfEventConnect:
		event.Type = events.TypeConnect
		event.Family = familyString(raw.Family)
		event.DestPort = raw.DestPort
		if raw.Family == 2 {
			event.DestIP = ipv4String(raw.DestAddr4)
		} else if raw.Family == 10 {
			event.DestIP = ipv6String(raw.DestAddr6[:])
		}
	default:
		return events.Event{}, fmt.Errorf("unknown event type %d", raw.Type)
	}

	return event, nil
}

func cString(raw []byte) string {
	if idx := bytes.IndexByte(raw, 0); idx >= 0 {
		raw = raw[:idx]
	}
	return strings.TrimSpace(string(raw))
}

func ipv4String(addr uint32) string {
	var raw [4]byte
	binary.LittleEndian.PutUint32(raw[:], addr)
	return net.IPv4(raw[0], raw[1], raw[2], raw[3]).String()
}

func ipv6String(raw []byte) string {
	if len(raw) != net.IPv6len {
		return ""
	}
	ip := net.IP(append([]byte(nil), raw...))
	if ip.IsUnspecified() {
		return ""
	}
	return ip.String()
}

func familyString(family uint16) string {
	switch family {
	case 2:
		return "ipv4"
	case 10:
		return "ipv6"
	default:
		return fmt.Sprintf("unknown(%d)", family)
	}
}
