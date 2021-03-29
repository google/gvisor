// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package strace

import (
	"fmt"
	"strings"

	"gvisor.dev/gvisor/pkg/abi"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/kernel"

	"gvisor.dev/gvisor/pkg/hostarch"
)

// signalNames contains the names of all named signals.
var signalNames = abi.ValueSet{
	uint64(linux.SIGABRT):   "SIGABRT",
	uint64(linux.SIGALRM):   "SIGALRM",
	uint64(linux.SIGBUS):    "SIGBUS",
	uint64(linux.SIGCHLD):   "SIGCHLD",
	uint64(linux.SIGCONT):   "SIGCONT",
	uint64(linux.SIGFPE):    "SIGFPE",
	uint64(linux.SIGHUP):    "SIGHUP",
	uint64(linux.SIGILL):    "SIGILL",
	uint64(linux.SIGINT):    "SIGINT",
	uint64(linux.SIGIO):     "SIGIO",
	uint64(linux.SIGKILL):   "SIGKILL",
	uint64(linux.SIGPIPE):   "SIGPIPE",
	uint64(linux.SIGPROF):   "SIGPROF",
	uint64(linux.SIGPWR):    "SIGPWR",
	uint64(linux.SIGQUIT):   "SIGQUIT",
	uint64(linux.SIGSEGV):   "SIGSEGV",
	uint64(linux.SIGSTKFLT): "SIGSTKFLT",
	uint64(linux.SIGSTOP):   "SIGSTOP",
	uint64(linux.SIGSYS):    "SIGSYS",
	uint64(linux.SIGTERM):   "SIGTERM",
	uint64(linux.SIGTRAP):   "SIGTRAP",
	uint64(linux.SIGTSTP):   "SIGTSTP",
	uint64(linux.SIGTTIN):   "SIGTTIN",
	uint64(linux.SIGTTOU):   "SIGTTOU",
	uint64(linux.SIGURG):    "SIGURG",
	uint64(linux.SIGUSR1):   "SIGUSR1",
	uint64(linux.SIGUSR2):   "SIGUSR2",
	uint64(linux.SIGVTALRM): "SIGVTALRM",
	uint64(linux.SIGWINCH):  "SIGWINCH",
	uint64(linux.SIGXCPU):   "SIGXCPU",
	uint64(linux.SIGXFSZ):   "SIGXFSZ",
}

var signalMaskActions = abi.ValueSet{
	linux.SIG_BLOCK:   "SIG_BLOCK",
	linux.SIG_UNBLOCK: "SIG_UNBLOCK",
	linux.SIG_SETMASK: "SIG_SETMASK",
}

var sigActionFlags = abi.FlagSet{
	{
		Flag: linux.SA_NOCLDSTOP,
		Name: "SA_NOCLDSTOP",
	},
	{
		Flag: linux.SA_NOCLDWAIT,
		Name: "SA_NOCLDWAIT",
	},
	{
		Flag: linux.SA_SIGINFO,
		Name: "SA_SIGINFO",
	},
	{
		Flag: linux.SA_RESTORER,
		Name: "SA_RESTORER",
	},
	{
		Flag: linux.SA_ONSTACK,
		Name: "SA_ONSTACK",
	},
	{
		Flag: linux.SA_RESTART,
		Name: "SA_RESTART",
	},
	{
		Flag: linux.SA_NODEFER,
		Name: "SA_NODEFER",
	},
	{
		Flag: linux.SA_RESETHAND,
		Name: "SA_RESETHAND",
	},
}

func sigSet(t *kernel.Task, addr hostarch.Addr) string {
	if addr == 0 {
		return "null"
	}

	var b [linux.SignalSetSize]byte
	if _, err := t.CopyInBytes(addr, b[:]); err != nil {
		return fmt.Sprintf("%#x (error copying sigset: %v)", addr, err)
	}

	set := linux.SignalSet(hostarch.ByteOrder.Uint64(b[:]))

	return fmt.Sprintf("%#x %s", addr, formatSigSet(set))
}

func formatSigSet(set linux.SignalSet) string {
	var signals []string
	linux.ForEachSignal(set, func(sig linux.Signal) {
		signals = append(signals, signalNames.ParseDecimal(uint64(sig)))
	})

	return fmt.Sprintf("[%v]", strings.Join(signals, " "))
}

func sigAction(t *kernel.Task, addr hostarch.Addr) string {
	if addr == 0 {
		return "null"
	}

	sa, err := t.CopyInSignalAct(addr)
	if err != nil {
		return fmt.Sprintf("%#x (error copying sigaction: %v)", addr, err)
	}

	var handler string
	switch sa.Handler {
	case linux.SIG_IGN:
		handler = "SIG_IGN"
	case linux.SIG_DFL:
		handler = "SIG_DFL"
	default:
		handler = fmt.Sprintf("%#x", sa.Handler)
	}

	return fmt.Sprintf("%#x {Handler: %s, Flags: %s, Restorer: %#x, Mask: %s}", addr, handler, sigActionFlags.Parse(sa.Flags), sa.Restorer, formatSigSet(sa.Mask))
}
