package rules

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/pranavrav09/RuntimeLens/internal/events"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Rules []Rule `yaml:"rules"`
}

type Rule struct {
	ID       string `yaml:"id"`
	Severity string `yaml:"severity"`
	Event    string `yaml:"event"`
	Window   string `yaml:"window"`
	Message  string `yaml:"message"`
	Match    Match  `yaml:"match"`
}

type Match struct {
	PathGlobs        []string `yaml:"path_globs"`
	DestPorts        []uint16 `yaml:"dest_ports"`
	DestCIDRs        []string `yaml:"dest_cidrs"`
	ExecArgvContains []string `yaml:"exec_argv_contains"`
	ConnectPorts     []uint16 `yaml:"connect_ports"`
	ConnectCIDRs     []string `yaml:"connect_cidrs"`
}

type Engine struct {
	rules      []compiledRule
	history    map[workloadKey][]events.Event
	lastAlerts map[string]time.Time
	maxWindow  time.Duration
}

type workloadKey struct {
	cgroupID uint64
	pid      uint32
}

type compiledRule struct {
	Rule
	window      time.Duration
	destNets    []*net.IPNet
	connectNets []*net.IPNet
}

func LoadFile(path string) (*Engine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rules: %w", err)
	}

	var cfg Config
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse rules: %w", err)
	}

	return NewEngine(cfg)
}

func NewEngine(cfg Config) (*Engine, error) {
	engine := &Engine{
		history:    make(map[workloadKey][]events.Event),
		lastAlerts: make(map[string]time.Time),
		maxWindow:  10 * time.Second,
	}

	if len(cfg.Rules) == 0 {
		return nil, fmt.Errorf("at least one rule is required")
	}
	ids := make(map[string]struct{}, len(cfg.Rules))
	for _, rule := range cfg.Rules {
		if _, duplicate := ids[rule.ID]; duplicate {
			return nil, fmt.Errorf("duplicate rule id %q", rule.ID)
		}
		compiled, err := compileRule(rule)
		if err != nil {
			return nil, err
		}

		if compiled.window > engine.maxWindow {
			engine.maxWindow = compiled.window
		}

		engine.rules = append(engine.rules, compiled)
		ids[rule.ID] = struct{}{}
	}

	return engine, nil
}

func (e *Engine) Evaluate(event events.Event) []events.Alert {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	key := scopeFor(event)
	e.remember(key, event)

	var alerts []events.Alert
	for _, rule := range e.rules {
		switch rule.Event {
		case "file":
			if event.Type == events.TypeFile && rule.matchesFile(event) {
				alerts = append(alerts, alertFor(rule, event))
			}
		case "connect":
			if event.Type == events.TypeConnect && rule.matchesConnect(event, false) {
				alerts = append(alerts, alertFor(rule, event))
			}
		case "exec":
			if event.Type == events.TypeExec && rule.matchesExec(event) {
				alerts = append(alerts, alertFor(rule, event))
			}
		case "correlation":
			if rule.matchesCorrelation(e.history[key], event.Timestamp) && e.markCorrelationAlert(rule, event) {
				alerts = append(alerts, alertFor(rule, event))
			}
		}
	}

	return alerts
}

func compileRule(rule Rule) (compiledRule, error) {
	if rule.ID == "" {
		return compiledRule{}, fmt.Errorf("rule id is required")
	}
	if rule.Event == "" {
		return compiledRule{}, fmt.Errorf("rule %q: event is required", rule.ID)
	}
	switch rule.Event {
	case "exec", "file", "connect", "correlation":
	default:
		return compiledRule{}, fmt.Errorf("rule %q: unsupported event %q", rule.ID, rule.Event)
	}
	if rule.Severity == "" {
		rule.Severity = "medium"
	}
	switch rule.Severity {
	case "low", "medium", "high", "critical":
	default:
		return compiledRule{}, fmt.Errorf("rule %q: unsupported severity %q", rule.ID, rule.Severity)
	}
	if rule.Event == "correlation" {
		if len(rule.Match.ExecArgvContains) == 0 {
			return compiledRule{}, fmt.Errorf("rule %q: correlation requires exec_argv_contains", rule.ID)
		}
		if len(rule.Match.ConnectPorts) == 0 && len(rule.Match.ConnectCIDRs) == 0 {
			return compiledRule{}, fmt.Errorf("rule %q: correlation requires connect_ports or connect_cidrs", rule.ID)
		}
	}

	compiled := compiledRule{Rule: rule, window: 5 * time.Second}

	if rule.Window != "" {
		window, err := time.ParseDuration(rule.Window)
		if err != nil {
			return compiledRule{}, fmt.Errorf("rule %q: invalid window: %w", rule.ID, err)
		}
		if window <= 0 {
			return compiledRule{}, fmt.Errorf("rule %q: window must be positive", rule.ID)
		}
		compiled.window = window
	}

	var err error
	compiled.destNets, err = parseNetworks(rule.Match.DestCIDRs)
	if err != nil {
		return compiledRule{}, fmt.Errorf("rule %q: invalid dest_cidrs: %w", rule.ID, err)
	}

	compiled.connectNets, err = parseNetworks(rule.Match.ConnectCIDRs)
	if err != nil {
		return compiledRule{}, fmt.Errorf("rule %q: invalid connect_cidrs: %w", rule.ID, err)
	}

	return compiled, nil
}

func parseNetworks(values []string) ([]*net.IPNet, error) {
	var networks []*net.IPNet
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}

		if strings.Contains(value, "/") {
			_, network, err := net.ParseCIDR(value)
			if err != nil {
				return nil, err
			}
			networks = append(networks, network)
			continue
		}

		ip := net.ParseIP(value)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP %q", value)
		}
		mask := net.CIDRMask(128, 128)
		if ip.To4() != nil {
			mask = net.CIDRMask(32, 32)
			ip = ip.To4()
		}
		networks = append(networks, &net.IPNet{IP: ip, Mask: mask})
	}

	return networks, nil
}

func scopeFor(event events.Event) workloadKey {
	if event.CgroupID != 0 {
		return workloadKey{cgroupID: event.CgroupID}
	}
	return workloadKey{pid: event.PID}
}

func (e *Engine) remember(key workloadKey, event events.Event) {
	history := append(e.history[key], event)
	cutoff := event.Timestamp.Add(-e.maxWindow)

	keep := history[:0]
	for _, candidate := range history {
		if candidate.Timestamp.After(cutoff) || candidate.Timestamp.Equal(cutoff) {
			keep = append(keep, candidate)
		}
	}

	e.history[key] = keep
}

func (rule compiledRule) matchesFile(event events.Event) bool {
	if len(rule.Match.PathGlobs) == 0 {
		return true
	}

	for _, pattern := range rule.Match.PathGlobs {
		if ok, _ := filepath.Match(pattern, event.Path); ok {
			return true
		}
	}

	return false
}

func (rule compiledRule) matchesConnect(event events.Event, correlation bool) bool {
	ports := rule.Match.DestPorts
	networks := rule.destNets
	if correlation {
		ports = rule.Match.ConnectPorts
		networks = rule.connectNets
	}

	portMatched := len(ports) == 0 || slices.Contains(ports, event.DestPort)
	networkMatched := len(networks) == 0 || ipInNetworks(event.DestIP, networks)

	return portMatched && networkMatched
}

func (rule compiledRule) matchesExec(event events.Event) bool {
	if len(rule.Match.ExecArgvContains) == 0 {
		return true
	}

	haystack := strings.ToLower(strings.Join(append([]string{event.Path}, event.Args...), " "))
	for _, needle := range rule.Match.ExecArgvContains {
		if !strings.Contains(haystack, strings.ToLower(needle)) {
			return false
		}
	}

	return true
}

func (rule compiledRule) matchesCorrelation(history []events.Event, now time.Time) bool {
	cutoff := now.Add(-rule.window)
	hasExec := len(rule.Match.ExecArgvContains) == 0
	hasConnect := len(rule.Match.ConnectPorts) == 0 && len(rule.Match.ConnectCIDRs) == 0

	for _, event := range history {
		if event.Timestamp.Before(cutoff) {
			continue
		}

		switch event.Type {
		case events.TypeExec:
			if rule.matchesExec(event) {
				hasExec = true
			}
		case events.TypeConnect:
			if rule.matchesConnect(event, true) {
				hasConnect = true
			}
		}
	}

	return hasExec && hasConnect
}

func (e *Engine) markCorrelationAlert(rule compiledRule, event events.Event) bool {
	scope := scopeFor(event)
	key := fmt.Sprintf("%s:%d:%d", rule.ID, scope.cgroupID, scope.pid)
	last, ok := e.lastAlerts[key]
	if ok && event.Timestamp.Sub(last) < rule.window {
		return false
	}

	e.lastAlerts[key] = event.Timestamp
	return true
}

func ipInNetworks(raw string, networks []*net.IPNet) bool {
	ip := net.ParseIP(raw)
	if ip == nil {
		return false
	}

	for _, network := range networks {
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

func alertFor(rule compiledRule, event events.Event) events.Alert {
	message := rule.Message
	if message == "" {
		message = fmt.Sprintf("rule %s matched", rule.ID)
	}

	return events.Alert{
		Type:      "alert",
		RuleID:    rule.ID,
		Severity:  rule.Severity,
		EventType: event.Type,
		Message:   message,
		Timestamp: event.Timestamp,
		PID:       event.PID,
		UID:       event.UID,
		CgroupID:  event.CgroupID,
		Job:       event.Job,
		Process:   event.Process,
		Path:      event.Path,
		Args:      event.Args,
		DestIP:    event.DestIP,
		DestPort:  event.DestPort,
	}
}
