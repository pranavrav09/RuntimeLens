package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/pranavrav09/RuntimeLens/internal/collector"
	"github.com/pranavrav09/RuntimeLens/internal/jobscope"
	jsonout "github.com/pranavrav09/RuntimeLens/internal/output"
	"github.com/pranavrav09/RuntimeLens/internal/rules"
)

type stringList []string

func (values *stringList) String() string { return fmt.Sprint([]string(*values)) }

func (values *stringList) Set(value string) error {
	*values = append(*values, value)
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "runtimelens: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var jobSpecs stringList
	rulesPath := flag.String("rules", "rules/default.yaml", "path to YAML detection rules")
	emitEvents := flag.Bool("emit-events", false, "emit raw events as JSON in addition to alerts")
	flag.Var(&jobSpecs, "job", "trace LABEL=CGROUP_PATH (repeatable; empty means all jobs)")
	flag.Parse()

	resolved, err := jobscope.Resolve(jobSpecs)
	if err != nil {
		return err
	}
	targets := make([]collector.Target, 0, len(resolved))
	for _, target := range resolved {
		targets = append(targets, collector.Target{CgroupID: target.CgroupID, Job: target.Job})
		fmt.Fprintf(os.Stderr, "tracking job=%s cgroup_id=%d path=%s\n",
			target.Job, target.CgroupID, target.Path)
	}

	engine, err := rules.LoadFile(*rulesPath)
	if err != nil {
		return err
	}
	sensor, err := collector.New(collector.Options{Targets: targets})
	if err != nil {
		return err
	}
	defer sensor.Close()

	for _, warning := range sensor.Warnings() {
		fmt.Fprintf(os.Stderr, "warning: %s\n", warning)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	eventCh, errCh := sensor.Events(ctx)
	writer := jsonout.NewJSONWriter(os.Stdout)

	for {
		select {
		case event, ok := <-eventCh:
			if !ok {
				return nil
			}
			if *emitEvents {
				if err := writer.WriteEvent(event); err != nil {
					return fmt.Errorf("write event: %w", err)
				}
			}
			for _, alert := range engine.Evaluate(event) {
				if err := writer.WriteAlert(alert); err != nil {
					return fmt.Errorf("write alert: %w", err)
				}
			}
		case err, ok := <-errCh:
			if ok && err != nil {
				return err
			}
		case <-ctx.Done():
			return nil
		}
	}
}
