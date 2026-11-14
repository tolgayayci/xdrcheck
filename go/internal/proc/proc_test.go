package proc

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The test binary doubles as the child: with XDRCHECK_PROC_HELPER set it runs one helper behaviour and exits.
func TestMain(m *testing.M) {
	if mode := os.Getenv("XDRCHECK_PROC_HELPER"); mode != "" {
		helper(mode)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

var sink [][]byte

func helper(mode string) {
	name, arg, _ := strings.Cut(mode, ":")
	switch name {
	case "exit":
		fmt.Println("hello from the child")
		fmt.Fprintln(os.Stderr, "a line on stderr")
		time.Sleep(300 * time.Millisecond) // long enough for the supervisor to sample the scope
		n, _ := strconv.Atoi(arg)
		os.Exit(n)
	case "sleep":
		d, _ := time.ParseDuration(arg)
		time.Sleep(d)
	case "alloc": // allocate arg MiB in 8 MiB chunks, touching every page
		mib, _ := strconv.Atoi(arg)
		for i := 0; i < mib/8; i++ {
			b := make([]byte, 8<<20)
			for j := 0; j < len(b); j += 4096 {
				b[j] = 1
			}
			sink = append(sink, b)
			time.Sleep(2 * time.Millisecond)
		}
		fmt.Println("allocated", mib, "MiB")
	case "spawn": // start a grandchild that sleeps, record its pid in arg, then sleep
		gc := exec.Command(os.Args[0])
		gc.Env = append(os.Environ(), "XDRCHECK_PROC_HELPER=sleep:60s")
		if err := gc.Start(); err != nil {
			os.Exit(3)
		}
		os.WriteFile(arg, []byte(strconv.Itoa(gc.Process.Pid)), 0o644)
		time.Sleep(60 * time.Second)
	case "spawn-alloc", "wrap-alloc": // run a grandchild (in a process group of its own) that allocates arg MiB
		gc := exec.Command(os.Args[0])
		gc.Env = append(os.Environ(), "XDRCHECK_PROC_HELPER=alloc:"+arg)
		gc.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		err := gc.Run()
		fmt.Println("grandchild:", err)
		time.Sleep(300 * time.Millisecond) // long enough for the supervisor to sample the scope
		if ws, ok := gc.ProcessState.Sys().(syscall.WaitStatus); ok && ws.Signaled() && name == "wrap-alloc" {
			os.Exit(128 + int(ws.Signal())) // as a shell reports its command's signal
		}
	case "fit": // print the soft memory limit taken from the group
		fmt.Println("limit", FitRuntimeToGroup(0.5))
	case "flood": // write arg bytes to stdout
		n, _ := strconv.Atoi(arg)
		os.Stdout.Write(bytes.Repeat([]byte("x"), n))
	case "echo":
		buf := make([]byte, 1024)
		n, _ := os.Stdin.Read(buf)
		os.Stdout.Write(bytes.ToUpper(buf[:n]))
	default:
		os.Exit(99)
	}
}

func helperSpec(mode string) Spec {
	return Spec{Path: os.Args[0], Env: append(os.Environ(), "XDRCHECK_PROC_HELPER="+mode), Name: "test"}
}

func needCgroup(t *testing.T) {
	t.Helper()
	if Available() != Cgroup {
		t.Skip("no cgroup v2 user scope on this host")
	}
}

func TestNormalExit(t *testing.T) {
	for _, mech := range []Mechanism{None, Rlimit, Cgroup} {
		t.Run(string(mech), func(t *testing.T) {
			if mech == Cgroup {
				needCgroup(t)
			}
			s := helperSpec("exit:3")
			s.Mechanism = mech
			s.Limits = Limits{Deadline: 30 * time.Second, MemoryMax: 1 << 30, AddressSpaceMax: 64 << 30}
			r, err := Run(context.Background(), s)
			if err != nil {
				t.Fatal(err)
			}
			if r.ExitCode != 3 || r.Signal != 0 || r.TimedOut || r.MemoryCapHit || r.Mechanism != mech {
				t.Errorf("result %+v", r)
			}
			if !strings.Contains(string(r.Stdout.Data), "hello from the child") || !strings.Contains(string(r.Stderr.Data), "stderr") {
				t.Errorf("tails: %q %q", r.Stdout.Data, r.Stderr.Data)
			}
			if r.PeakRSSBytes <= 0 {
				t.Errorf("no peak RSS")
			}
			if mech == Cgroup && (r.GroupPeakBytes <= 0 || !strings.HasPrefix(r.Unit, "xdrcheck-test-")) {
				t.Errorf("cgroup: unit %q, memory.peak %d, notes %v", r.Unit, r.GroupPeakBytes, r.Notes)
			}
		})
	}
	r, err := Run(context.Background(), helperSpec("exit:0"))
	if err != nil || r.ExitCode != 0 || r.Mechanism != None {
		t.Errorf("no limits: %+v %v", r, err)
	}
}

func TestMemoryCapCgroup(t *testing.T) {
	needCgroup(t)
	s := helperSpec("alloc:512")
	s.Limits = Limits{Deadline: 60 * time.Second, MemoryMax: 64 << 20}
	r, err := Run(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%+v", r)
	if !r.MemoryCapHit || r.Signal != syscall.SIGKILL || r.ExitCode != 137 || r.TimedOut || r.Mechanism != Cgroup {
		t.Errorf("want a memory kill: %+v", r)
	}
	if strings.Contains(string(r.Stdout.Data), "allocated") {
		t.Error("the child finished its allocation")
	}
}

func TestMemoryCapPolled(t *testing.T) {
	s := helperSpec("alloc:1024")
	s.Mechanism = Rlimit
	// A Go child reserves far more address space than it uses, so the address-space limit is set apart from
	// the resident-memory cap here.
	s.Limits = Limits{Deadline: 60 * time.Second, MemoryMax: 128 << 20, AddressSpaceMax: 64 << 30}
	r, err := Run(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%+v", r)
	if !r.MemoryCapHit || r.Signal != syscall.SIGKILL || r.GroupPeakBytes <= 128<<20 || r.Mechanism != Rlimit {
		t.Errorf("want a memory kill: %+v", r)
	}
}

// A descendant that runs out of memory is killed alone — by the kernel, or by the poller doing what the kernel
// would — and the child, which uses little, lives on: the supervisor counts the kill and adds none of its own.
func TestMemoryKillOfDescendant(t *testing.T) {
	for _, mech := range []Mechanism{Rlimit, Cgroup} {
		t.Run(string(mech), func(t *testing.T) {
			if mech == Cgroup {
				needCgroup(t)
			}
			s := helperSpec("spawn-alloc:1024")
			s.Mechanism = mech
			s.Limits = Limits{Deadline: 60 * time.Second, MemoryMax: 128 << 20, AddressSpaceMax: 64 << 30}
			c, err := Start(context.Background(), s)
			if err != nil {
				t.Fatal(err)
			}
			if n, ok := OOMKills(c.Pid()); !ok || n != 0 {
				t.Errorf("OOMKills at start: %d %v", n, ok)
			}
			r := c.Wait()
			t.Logf("%+v", r)
			if r.ExitCode != 0 || r.MemoryCapHit || r.OOMKills < 1 || r.Mechanism != mech {
				t.Errorf("want the child alive after its descendant's memory kill: %+v", r)
			}
			if !strings.Contains(string(r.Stdout.Data), "grandchild: signal: killed") {
				t.Errorf("stdout %q", r.Stdout.Data)
			}
			if _, ok := OOMKills(c.Pid()); ok {
				t.Error("OOMKills still answers for an ended child")
			}

			// A wrapper that passes its program's SIGKILL on as exit 137 ended for memory.
			s = helperSpec("wrap-alloc:1024")
			s.Mechanism = mech
			s.Limits = Limits{Deadline: 60 * time.Second, MemoryMax: 128 << 20, AddressSpaceMax: 64 << 30}
			r, err = Run(context.Background(), s)
			if err != nil {
				t.Fatal(err)
			}
			if r.ExitCode != 137 || !r.MemoryCapHit || r.OOMKills < 1 {
				t.Errorf("want a wrapper's memory end: %+v", r)
			}
		})
	}
}

// A Go child in a memory-limited group takes its soft memory limit from the group's memory.max.
func TestFitRuntimeToGroup(t *testing.T) {
	needCgroup(t)
	s := helperSpec("fit")
	s.Limits = Limits{Deadline: 30 * time.Second, MemoryMax: 256 << 20}
	r, err := Run(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(r.Stdout.Data)); got != fmt.Sprintf("limit %d", 128<<20) {
		t.Errorf("child said %q", got)
	}
	s.Env = append(s.Env, "GOMEMLIMIT=1GiB")
	if r, _ := Run(context.Background(), s); strings.TrimSpace(string(r.Stdout.Data)) != "limit 0" {
		t.Errorf("with GOMEMLIMIT set: %q", r.Stdout.Data)
	}
}

func TestDeadlineKillsGroup(t *testing.T) {
	for _, mech := range []Mechanism{None, Cgroup} {
		t.Run(string(mech), func(t *testing.T) {
			if mech == Cgroup {
				needCgroup(t)
			}
			pidFile := filepath.Join(t.TempDir(), "grandchild.pid")
			s := helperSpec("spawn:" + pidFile)
			s.Mechanism = mech
			s.Limits = Limits{Deadline: 1500 * time.Millisecond, MemoryMax: 1 << 30}
			start := time.Now()
			r, err := Run(context.Background(), s)
			if err != nil {
				t.Fatal(err)
			}
			if !r.TimedOut || r.Signal != syscall.SIGKILL || r.MemoryCapHit {
				t.Errorf("want a timeout kill: %+v", r)
			}
			if el := time.Since(start); el > 10*time.Second {
				t.Errorf("took %s", el)
			}
			data, err := os.ReadFile(pidFile)
			if err != nil {
				t.Fatalf("grandchild never started: %v", err)
			}
			gpid, _ := strconv.Atoi(string(data))
			if !gone(gpid, 3*time.Second) {
				t.Errorf("grandchild %d survived the group kill", gpid)
			}
		})
	}
}

func TestGraceAndCancel(t *testing.T) {
	s := helperSpec("sleep:30s")
	s.Grace = 200 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	c, err := Start(ctx, s)
	if err != nil {
		t.Fatal(err)
	}
	time.AfterFunc(200*time.Millisecond, cancel)
	r := c.Wait()
	// The helper does not handle SIGTERM, so it dies of it within the grace period.
	if !r.Canceled || r.Signal != syscall.SIGTERM || r.TimedOut {
		t.Errorf("%+v", r)
	}
}

func TestTailBoundedAndTee(t *testing.T) {
	s := helperSpec("flood:1048576")
	s.TailBytes = 1000
	var full bytes.Buffer
	s.Stdout = &full
	r, err := Run(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Stdout.Data) != 1000 || r.Stdout.Total != 1<<20 || !r.Stdout.Truncated() || full.Len() != 1<<20 {
		t.Errorf("tail %d bytes of %d, tee %d", len(r.Stdout.Data), r.Stdout.Total, full.Len())
	}
}

func TestStdin(t *testing.T) {
	s := helperSpec("echo")
	s.Stdin = strings.NewReader("ping")
	r, err := Run(context.Background(), s)
	if err != nil || string(r.Stdout.Data) != "PING" {
		t.Errorf("%q %v", r.Stdout.Data, err)
	}
}

func TestStartErrors(t *testing.T) {
	if _, err := Start(context.Background(), Spec{Path: "xdrcheck-no-such-binary"}); err == nil {
		t.Error("missing binary accepted")
	}
}

func gone(pid int, within time.Duration) bool {
	end := time.Now().Add(within)
	for time.Now().Before(end) {
		if err := syscall.Kill(pid, 0); err == syscall.ESRCH {
			return true
		}
		if data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)); err == nil && strings.Contains(string(data), ") Z ") {
			return true // killed, waiting to be reaped
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}
