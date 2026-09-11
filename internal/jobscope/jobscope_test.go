package jobscope

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveLabeledTarget(t *testing.T) {
	directory := t.TempDir()
	targets, err := Resolve([]string{"job-42=" + directory})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(targets) != 1 || targets[0].Job != "job-42" || targets[0].CgroupID == 0 {
		t.Fatalf("unexpected targets: %#v", targets)
	}
}

func TestResolveRejectsFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-cgroup")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Resolve([]string{path}); err == nil {
		t.Fatal("expected non-directory error")
	}
}
