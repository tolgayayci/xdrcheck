package walletbackend

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Socket directories carry the run's name prefix: a process makes <prefix>-<pid>-<n>, stale removal touches only
// its own prefix's directories of processes that are gone, and a path too long for a Unix socket is refused.
func TestSocketDirs(t *testing.T) {
	run := t.TempDir()
	const prefix = "xdrcheck-test-run42"
	dir, err := makeSocketDir(run, prefix)
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Base(dir)
	if pid, ok := socketDirPID(name, prefix); !ok || pid != os.Getpid() {
		t.Fatalf("%s: pid %d %v", name, pid, ok)
	}
	if dir2, err := makeSocketDir(run, prefix); err != nil || dir2 == dir {
		t.Fatalf("second directory %s %v", dir2, err)
	}
	for _, n := range []string{"xdrcheck-test-run4-1-1", "xdrcheck-test-run42-x-1", "xdrcheck-test-run42-1", "pg-1-123"} {
		if _, ok := socketDirPID(n, prefix); ok {
			t.Errorf("%s parsed as a directory of %s", n, prefix)
		}
	}

	// A gone process of this prefix (no process has PID 2^22+1 above the default pid_max), and the same PID under
	// another prefix and in the old pg-<pid>- form, which belong to other runs.
	const gone = 1<<22 + 1
	mine := filepath.Join(run, prefix+"-"+strconv.Itoa(gone)+"-1")
	other := filepath.Join(run, "xdrcheck-other-run7-"+strconv.Itoa(gone)+"-1")
	old := filepath.Join(run, "pg-"+strconv.Itoa(gone)+"-123")
	for _, d := range []string{mine, other, old} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	removeStaleSockets(run, prefix, "unused@sha256:0")
	for d, want := range map[string]bool{mine: false, other: true, old: true, dir: true} {
		if _, err := os.Stat(d); (err == nil) != want {
			t.Errorf("%s: present %v, want %v", d, err == nil, want)
		}
	}

	if _, err := makeSocketDir(filepath.Join(run, strings.Repeat("d", 100)), prefix); err == nil || !strings.Contains(err.Error(), "Unix socket") {
		t.Errorf("an over-long socket path: %v", err)
	}
}
