//go:build linux

package proc

import "syscall"

// childAttr puts the child in its own process group and kills it when this process dies.
func childAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
}
