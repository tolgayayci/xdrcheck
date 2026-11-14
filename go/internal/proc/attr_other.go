//go:build !linux

package proc

import "syscall"

// childAttr puts the child in its own process group. Outside Linux there is no parent-death signal; the
// caller's deadline and group kill still stop it.
func childAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true}
}
