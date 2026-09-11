package jobscope

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

type Target struct {
	CgroupID uint64
	Job      string
	Path     string
}

// Resolve converts LABEL=PATH or PATH specifications to cgroup IDs. On cgroup
// v2 the ID returned by bpf_get_current_cgroup_id is the directory inode.
func Resolve(specs []string) ([]Target, error) {
	targets := make([]Target, 0, len(specs))
	seen := make(map[uint64]string)
	for _, spec := range specs {
		label, path := splitSpec(spec)
		absolute, err := filepath.Abs(path)
		if err != nil {
			return nil, fmt.Errorf("resolve cgroup path %q: %w", path, err)
		}
		info, err := os.Stat(absolute)
		if err != nil {
			return nil, fmt.Errorf("stat cgroup %q: %w", absolute, err)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("cgroup %q is not a directory", absolute)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Ino == 0 {
			return nil, fmt.Errorf("read inode for cgroup %q", absolute)
		}
		id := uint64(stat.Ino)
		if existing, duplicate := seen[id]; duplicate {
			if existing != label {
				return nil, fmt.Errorf("cgroup %q has conflicting labels %q and %q", absolute, existing, label)
			}
			continue
		}
		seen[id] = label
		targets = append(targets, Target{CgroupID: id, Job: label, Path: absolute})
	}
	return targets, nil
}

func splitSpec(spec string) (string, string) {
	if label, path, found := strings.Cut(spec, "="); found && label != "" && path != "" {
		return label, path
	}
	return filepath.Base(filepath.Clean(spec)), spec
}
