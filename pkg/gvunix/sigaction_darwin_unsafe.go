// Copyright 2021 The gVisor Authors.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build darwin && arm64
// +build darwin,arm64

package gvunix

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Set in assembly.
var libc_sigaction_trampoline_addr uintptr

//go:cgo_import_dynamic libc_sigaction sigaction "/usr/lib/libSystem.B.dylib"

// SigactionOpts is a Go-ified struct sigaction (see sigaction(2)).
type SigactionOpts struct {
	Handler uintptr
	Mask    SigactionMask
	Flags   SigactionFlags
}

// TODO: We don't need all of this.

// SigactionMask is the list of signals to block while Handler runs.
type SigactionMask struct {
	SIGHUP    bool
	SIGINT    bool
	SIGQUIT   bool
	SIGILL    bool
	SIGTRAP   bool
	SIGABRT   bool
	SIGEMT    bool
	SIGFPE    bool
	SIGKILL   bool
	SIGBUS    bool
	SIGSEGV   bool
	SIGSYS    bool
	SIGPIPE   bool
	SIGALRM   bool
	SIGTERM   bool
	SIGURG    bool
	SIGSTOP   bool
	SIGTSTP   bool
	SIGCONT   bool
	SIGCHLD   bool
	SIGTTIN   bool
	SIGTTOU   bool
	SIGIO     bool
	SIGXCPU   bool
	SIGXFSZ   bool
	SIGVTALRM bool
	SIGPROF   bool
	SIGWINCH  bool
	SIGINFO   bool
	SIGUSR1   bool
	SIGUSR2   bool
}

func sigmask(sig syscall.Signal) uint32 {
	return 1 << (sig - 1)
}

var supportedSignals = uint32(sigmask(unix.SIGHUP) |
	sigmask(unix.SIGINT) |
	sigmask(unix.SIGQUIT) |
	sigmask(unix.SIGILL) |
	sigmask(unix.SIGTRAP) |
	sigmask(unix.SIGABRT) |
	sigmask(unix.SIGEMT) |
	sigmask(unix.SIGFPE) |
	sigmask(unix.SIGKILL) |
	sigmask(unix.SIGBUS) |
	sigmask(unix.SIGSEGV) |
	sigmask(unix.SIGSYS) |
	sigmask(unix.SIGPIPE) |
	sigmask(unix.SIGALRM) |
	sigmask(unix.SIGTERM) |
	sigmask(unix.SIGURG) |
	sigmask(unix.SIGSTOP) |
	sigmask(unix.SIGTSTP) |
	sigmask(unix.SIGCONT) |
	sigmask(unix.SIGCHLD) |
	sigmask(unix.SIGTTIN) |
	sigmask(unix.SIGTTOU) |
	sigmask(unix.SIGIO) |
	sigmask(unix.SIGXCPU) |
	sigmask(unix.SIGXFSZ) |
	sigmask(unix.SIGVTALRM) |
	sigmask(unix.SIGPROF) |
	sigmask(unix.SIGWINCH) |
	sigmask(unix.SIGINFO) |
	sigmask(unix.SIGUSR1) |
	sigmask(unix.SIGUSR2))

func (sm SigactionMask) ToHost() uint32 {
	var ret uint32
	if sm.SIGHUP {
		ret |= sigmask(unix.SIGHUP)
	}
	if sm.SIGINT {
		ret |= sigmask(unix.SIGINT)
	}
	if sm.SIGQUIT {
		ret |= sigmask(unix.SIGQUIT)
	}
	if sm.SIGILL {
		ret |= sigmask(unix.SIGILL)
	}
	if sm.SIGTRAP {
		ret |= sigmask(unix.SIGTRAP)
	}
	if sm.SIGABRT {
		ret |= sigmask(unix.SIGABRT)
	}
	if sm.SIGEMT {
		ret |= sigmask(unix.SIGEMT)
	}
	if sm.SIGFPE {
		ret |= sigmask(unix.SIGFPE)
	}
	if sm.SIGKILL {
		ret |= sigmask(unix.SIGKILL)
	}
	if sm.SIGBUS {
		ret |= sigmask(unix.SIGBUS)
	}
	if sm.SIGSEGV {
		ret |= sigmask(unix.SIGSEGV)
	}
	if sm.SIGSYS {
		ret |= sigmask(unix.SIGSYS)
	}
	if sm.SIGPIPE {
		ret |= sigmask(unix.SIGPIPE)
	}
	if sm.SIGALRM {
		ret |= sigmask(unix.SIGALRM)
	}
	if sm.SIGTERM {
		ret |= sigmask(unix.SIGTERM)
	}
	if sm.SIGURG {
		ret |= sigmask(unix.SIGURG)
	}
	if sm.SIGSTOP {
		ret |= sigmask(unix.SIGSTOP)
	}
	if sm.SIGTSTP {
		ret |= sigmask(unix.SIGTSTP)
	}
	if sm.SIGCONT {
		ret |= sigmask(unix.SIGCONT)
	}
	if sm.SIGCHLD {
		ret |= sigmask(unix.SIGCHLD)
	}
	if sm.SIGTTIN {
		ret |= sigmask(unix.SIGTTIN)
	}
	if sm.SIGTTOU {
		ret |= sigmask(unix.SIGTTOU)
	}
	if sm.SIGIO {
		ret |= sigmask(unix.SIGIO)
	}
	if sm.SIGXCPU {
		ret |= sigmask(unix.SIGXCPU)
	}
	if sm.SIGXFSZ {
		ret |= sigmask(unix.SIGXFSZ)
	}
	if sm.SIGVTALRM {
		ret |= sigmask(unix.SIGVTALRM)
	}
	if sm.SIGPROF {
		ret |= sigmask(unix.SIGPROF)
	}
	if sm.SIGWINCH {
		ret |= sigmask(unix.SIGWINCH)
	}
	if sm.SIGINFO {
		ret |= sigmask(unix.SIGINFO)
	}
	if sm.SIGUSR1 {
		ret |= sigmask(unix.SIGUSR1)
	}
	if sm.SIGUSR2 {
		ret |= sigmask(unix.SIGUSR2)
	}
	return ret
}

func SigactionMaskFrom(host uint32) SigactionMask {
	if unsupported := host &^ supportedSignals; unsupported != 0 {
		panic(fmt.Sprintf("unsupported signal: 0x%x. Host is 0x%x, supported is 0x%x", unsupported, host, supportedSignals))
	}

	var ret SigactionMask
	if host&sigmask(unix.SIGHUP) != 0 {
		ret.SIGHUP = true
	}
	if host&sigmask(unix.SIGINT) != 0 {
		ret.SIGINT = true
	}
	if host&sigmask(unix.SIGQUIT) != 0 {
		ret.SIGQUIT = true
	}
	if host&sigmask(unix.SIGILL) != 0 {
		ret.SIGILL = true
	}
	if host&sigmask(unix.SIGTRAP) != 0 {
		ret.SIGTRAP = true
	}
	if host&sigmask(unix.SIGABRT) != 0 {
		ret.SIGABRT = true
	}
	if host&sigmask(unix.SIGEMT) != 0 {
		ret.SIGEMT = true
	}
	if host&sigmask(unix.SIGFPE) != 0 {
		ret.SIGFPE = true
	}
	if host&sigmask(unix.SIGKILL) != 0 {
		ret.SIGKILL = true
	}
	if host&sigmask(unix.SIGBUS) != 0 {
		ret.SIGBUS = true
	}
	if host&sigmask(unix.SIGSEGV) != 0 {
		ret.SIGSEGV = true
	}
	if host&sigmask(unix.SIGSYS) != 0 {
		ret.SIGSYS = true
	}
	if host&sigmask(unix.SIGPIPE) != 0 {
		ret.SIGPIPE = true
	}
	if host&sigmask(unix.SIGALRM) != 0 {
		ret.SIGALRM = true
	}
	if host&sigmask(unix.SIGTERM) != 0 {
		ret.SIGTERM = true
	}
	if host&sigmask(unix.SIGURG) != 0 {
		ret.SIGURG = true
	}
	if host&sigmask(unix.SIGSTOP) != 0 {
		ret.SIGSTOP = true
	}
	if host&sigmask(unix.SIGTSTP) != 0 {
		ret.SIGTSTP = true
	}
	if host&sigmask(unix.SIGCONT) != 0 {
		ret.SIGCONT = true
	}
	if host&sigmask(unix.SIGCHLD) != 0 {
		ret.SIGCHLD = true
	}
	if host&sigmask(unix.SIGTTIN) != 0 {
		ret.SIGTTIN = true
	}
	if host&sigmask(unix.SIGTTOU) != 0 {
		ret.SIGTTOU = true
	}
	if host&sigmask(unix.SIGIO) != 0 {
		ret.SIGIO = true
	}
	if host&sigmask(unix.SIGXCPU) != 0 {
		ret.SIGXCPU = true
	}
	if host&sigmask(unix.SIGXFSZ) != 0 {
		ret.SIGXFSZ = true
	}
	if host&sigmask(unix.SIGVTALRM) != 0 {
		ret.SIGVTALRM = true
	}
	if host&sigmask(unix.SIGPROF) != 0 {
		ret.SIGPROF = true
	}
	if host&sigmask(unix.SIGWINCH) != 0 {
		ret.SIGWINCH = true
	}
	if host&sigmask(unix.SIGINFO) != 0 {
		ret.SIGINFO = true
	}
	if host&sigmask(unix.SIGUSR1) != 0 {
		ret.SIGUSR1 = true
	}
	if host&sigmask(unix.SIGUSR2) != 0 {
		ret.SIGUSR2 = true
	}
	return ret
}

// Mac sigaction flag values.
const (
	SA_ONSTACK   = 0x0001
	SA_RESTART   = 0x0002
	SA_RESETHAND = 0x0004
	SA_NOCLDSTOP = 0x0008
	SA_NODEFER   = 0x0010
	SA_NOCLDWAIT = 0x0020
	SA_SIGINFO   = 0x0040
	sa_supported = SA_ONSTACK | SA_RESTART | SA_RESETHAND | SA_NOCLDSTOP | SA_NODEFER | SA_NOCLDWAIT | SA_SIGINFO
)

// SigactionFlags affect signal handling behavior.
type SigactionFlags struct {
	// NoChildStop is SA_NOCLDSTOP.
	NoChildStop bool

	// NoChildWait is SA_NOCLDWAIT.
	NoChildWait bool

	// OnStack is SA_ONSTACK.
	OnStack bool

	// NoDefer is SA_NODEFER.
	NoDefer bool

	// ResetHandler is SA_RESETHAND.
	ResetHandler bool

	// Restart is SA_RESTART.
	Restart bool

	// Siginfo is SA_SIGINFO.
	Siginfo bool
}

func (sf SigactionFlags) ToHost() uint32 {
	var ret uint32
	if sf.NoChildStop {
		ret |= SA_NOCLDSTOP
	}
	if sf.NoChildWait {
		ret |= SA_NOCLDWAIT
	}
	if sf.OnStack {
		ret |= SA_ONSTACK
	}
	if sf.NoDefer {
		ret |= SA_NODEFER
	}
	if sf.ResetHandler {
		ret |= SA_RESETHAND
	}
	if sf.Restart {
		ret |= SA_RESTART
	}
	if sf.Siginfo {
		ret |= SA_SIGINFO
	}
	// return 67
	return ret
}

func SigactionFlagsFrom(host uint32) SigactionFlags {
	if unsupported := host &^ sa_supported; unsupported != 0 {
		panic(fmt.Sprintf("unsupported flags: 0x%x", unsupported))
	}

	var ret SigactionFlags
	if host&SA_NOCLDSTOP != 0 {
		ret.NoChildStop = true
	}
	if host&SA_NOCLDWAIT != 0 {
		ret.NoChildWait = true
	}
	if host&SA_ONSTACK != 0 {
		ret.OnStack = true
	}
	if host&SA_NODEFER != 0 {
		ret.NoDefer = true
	}
	if host&SA_RESETHAND != 0 {
		ret.ResetHandler = true
	}
	if host&SA_RESTART != 0 {
		ret.Restart = true
	}
	if host&SA_SIGINFO != 0 {
		ret.Siginfo = true
	}
	return ret
}

// abiSigaction is struct sigaction as needed by the libc API.
type abiSigaction struct {
	Handler uintptr
	Mask    uint32
	Flags   uint32
}

// Sigaction implements sigaction(2). It sets the action if sa is not nil and
// always returns the existing action.
func Sigaction(sig unix.Signal, sa *SigactionOpts) (SigactionOpts, error) {
	// Convert sa to an ABI-compatible version.
	var abiSa *abiSigaction
	if sa != nil {
		abiSa = &abiSigaction{
			Handler: sa.Handler,
			Mask:    sa.Mask.ToHost(),
			Flags:   sa.Flags.ToHost(),
		}
	}

	// Call into libc.
	var oldSa abiSigaction
	_, _, errno := syscall_syscall(libc_sigaction_trampoline_addr,
		uintptr(sig),
		uintptr(unsafe.Pointer(abiSa)),
		uintptr(unsafe.Pointer(&oldSa)))
	if errno != 0 {
		return SigactionOpts{}, errno
	}

	return SigactionOpts{
		Handler: oldSa.Handler,
		Mask:    SigactionMaskFrom(oldSa.Mask),
		Flags:   SigactionFlagsFrom(oldSa.Flags),
	}, nil
}
