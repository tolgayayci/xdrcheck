package proc

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// FitRuntimeToGroup sets this Go process's soft memory limit (runtime/debug.SetMemoryLimit) to fraction of the
// tightest memory.max of the cgroup v2 group it runs in and that group's ancestors, so that near the group's hard
// limit the garbage collector runs more often and returns freed memory to the system sooner, instead of the
// kernel killing the process at the limit with garbage still on its heap. It does nothing when GOMEMLIMIT is
// set or no group above the process has a memory.max. It returns the limit set, or 0.
func FitRuntimeToGroup(fraction float64) int64 {
	if os.Getenv("GOMEMLIMIT") != "" || fraction <= 0 || fraction > 1 {
		return 0
	}
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return 0
	}
	var group string
	for _, line := range strings.Split(string(data), "\n") {
		if p, ok := strings.CutPrefix(line, "0::"); ok {
			group = p
		}
	}
	if group == "" {
		return 0
	}
	var tightest int64
	for dir := "/sys/fs/cgroup" + strings.TrimSuffix(group, "/"); strings.HasPrefix(dir, "/sys/fs/cgroup/"); dir = filepath.Dir(dir) {
		// "max" does not parse as a number and is no limit.
		if v, err := readInt(dir + "/memory.max"); err == nil && v > 0 && (tightest == 0 || v < tightest) {
			tightest = v
		}
	}
	if tightest == 0 {
		return 0
	}
	limit := int64(float64(tightest) * fraction)
	debug.SetMemoryLimit(limit)
	return limit
}

// monitor samples the child's memory while it runs: under the cgroup mechanism the scope's memory.peak and
// memory.events (the kernel enforces the cap), otherwise (when a MemoryMax is set) the resident memory of the
// child's process group and descendants, which it compares against the cap itself.
type monitor struct {
	c         *Child
	overLimit chan string
	stopCh    chan struct{}
	stopped   chan struct{}

	mu        sync.Mutex
	cgDir     string
	peak      int64
	oomKills  int
	signalled bool
	// lastEventsRead is whether the latest sample could read memory.events. After the child has exited it
	// tells whether OOMKills is final or the scope was already gone.
	lastEventsRead bool
}

func startMonitor(c *Child) *monitor {
	m := &monitor{c: c, overLimit: make(chan string, 1), stopCh: make(chan struct{}), stopped: make(chan struct{})}
	active := c.mech == Cgroup || c.spec.Limits.MemoryMax > 0
	go func() {
		defer close(m.stopped)
		if !active {
			<-m.stopCh
			return
		}
		t := time.NewTicker(c.spec.Poll)
		defer t.Stop()
		for {
			m.sample()
			select {
			case <-m.stopCh:
				return
			case <-t.C:
			}
		}
	}()
	return m
}

// stop ends sampling and takes one last sample, while the scope may still exist.
func (m *monitor) stop() {
	close(m.stopCh)
	<-m.stopped
	if m.c.mech == Cgroup {
		m.sample()
	}
}

func (m *monitor) cgroupDir() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cgDir
}

func (m *monitor) fill(res *Result) {
	m.mu.Lock()
	defer m.mu.Unlock()
	res.GroupPeakBytes = m.peak
	res.OOMKills = m.oomKills
	if m.c.mech == Cgroup && m.cgDir == "" {
		res.Notes = append(res.Notes, "scope cgroup not observed (the child ended before it was found); no memory.peak")
	}
	if m.c.mech != Cgroup && m.c.spec.Limits.MemoryMax > 0 {
		res.Notes = append(res.Notes, fmt.Sprintf("memory cap enforced by polling process-group RSS every %s", m.c.spec.Poll))
	}
}

func (m *monitor) sample() {
	m.mu.Lock()
	defer m.mu.Unlock()
	limit := m.c.spec.Limits.MemoryMax
	if m.c.mech == Cgroup {
		if m.cgDir == "" {
			m.cgDir = findScope(m.c.pgid, m.c.unit)
			if m.cgDir == "" {
				return
			}
		}
		if v, err := readInt(m.cgDir + "/memory.peak"); err == nil && v > m.peak {
			m.peak = v
		}
		// The kernel has already enforced the cap by the time oom_kill moves; the count is only recorded.
		n, ok := readOOMKills(m.cgDir + "/memory.events")
		m.lastEventsRead = ok
		if ok && n > m.oomKills {
			m.oomKills = n
		}
		return
	}
	if limit <= 0 || m.signalled {
		return
	}
	procs := groupProcs(m.c.pgid)
	var rss int64
	var top procRSS
	for _, p := range procs {
		rss += p.rss
		if p.rss > top.rss {
			top = p
		}
	}
	if rss > m.peak {
		m.peak = rss
	}
	if rss <= limit {
		return
	}
	// What the kernel's out-of-memory killer would do in a cgroup: kill the largest process. When that is the
	// child itself the whole group goes; a descendant is killed alone and the child sees it die.
	if top.pid == 0 || top.pid == m.c.pgid {
		m.over(fmt.Sprintf("memory cap: process group resident memory %d bytes > %d", rss, limit))
		return
	}
	if syscall.Kill(top.pid, syscall.SIGKILL) == nil {
		m.oomKills++
	}
}

func (m *monitor) over(reason string) {
	if m.signalled {
		return
	}
	m.signalled = true
	m.overLimit <- reason
}

// findScope returns the cgroup directory of the named scope unit: the child's own cgroup once systemd-run has
// moved it there, or, when the child is already gone, the place the user manager puts transient scopes.
func findScope(pid int, unit string) string {
	if data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid)); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if p, ok := strings.CutPrefix(line, "0::"); ok && strings.HasSuffix(p, "/"+unit+".scope") {
				return "/sys/fs/cgroup" + p
			}
		}
	}
	uid := os.Getuid()
	std := fmt.Sprintf("/sys/fs/cgroup/user.slice/user-%d.slice/user@%d.service/app.slice/%s.scope", uid, uid, unit)
	if _, err := os.Stat(std); err == nil {
		return std
	}
	return ""
}

func readInt(file string) (int64, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
}

func readOOMKills(file string) (int, bool) {
	f, err := os.Open(file)
	if err != nil {
		return 0, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "oom_kill "); ok {
			n, err := strconv.Atoi(v)
			return n, err == nil
		}
	}
	return 0, false
}

type procRSS struct {
	pid int
	rss int64 // bytes
}

// groupProcs lists the processes of process group pgid and every descendant of its leader (a descendant may
// have made a group of its own), with their resident memory.
func groupProcs(pgid int) []procRSS {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	page := int64(os.Getpagesize())
	type stat struct {
		ppid, pgrp int
		rss        int64
	}
	all := map[int]stat{}
	for _, e := range entries {
		if e.Name()[0] < '0' || e.Name()[0] > '9' {
			continue
		}
		data, err := os.ReadFile("/proc/" + e.Name() + "/stat")
		if err != nil {
			continue
		}
		// Fields after the command name, which is in parentheses and may contain anything.
		i := bytes.LastIndexByte(data, ')')
		if i < 0 {
			continue
		}
		f := strings.Fields(string(data[i+1:]))
		if len(f) < 22 {
			continue
		}
		pid, _ := strconv.Atoi(e.Name())
		ppid, _ := strconv.Atoi(f[1])             // field 4: ppid
		pgrp, _ := strconv.Atoi(f[2])             // field 5: pgrp
		rss, _ := strconv.ParseInt(f[21], 10, 64) // field 24: rss in pages
		all[pid] = stat{ppid: ppid, pgrp: pgrp, rss: rss * page}
	}
	member := func(pid int) bool {
		for hops := 0; pid > 1 && hops < 64; hops++ {
			s, ok := all[pid]
			if !ok {
				return false
			}
			if pid == pgid || s.pgrp == pgid {
				return true
			}
			pid = s.ppid
		}
		return false
	}
	var out []procRSS
	for pid, s := range all {
		if member(pid) {
			out = append(out, procRSS{pid: pid, rss: s.rss})
		}
	}
	return out
}
