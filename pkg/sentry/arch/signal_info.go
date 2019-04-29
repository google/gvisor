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

package arch

// Possible values for SignalInfo.Code. These values originate from the Linux
// kernel's include/uapi/asm-generic/siginfo.h.
const (
	// SignalInfoUser (properly SI_USER) indicates that a signal was sent from
	// a kill() or raise() syscall.
	SignalInfoUser = 0

	// SignalInfoKernel (properly SI_KERNEL) indicates that the signal was sent
	// by the kernel.
	SignalInfoKernel = 0x80

	// SignalInfoTimer (properly SI_TIMER) indicates that the signal was sent
	// by an expired timer.
	SignalInfoTimer = -2

	// SignalInfoTkill (properly SI_TKILL) indicates that the signal was sent
	// from a tkill() or tgkill() syscall.
	SignalInfoTkill = -6

	// CLD_* codes are only meaningful for SIGCHLD.

	// CLD_EXITED indicates that a task exited.
	CLD_EXITED = 1

	// CLD_KILLED indicates that a task was killed by a signal.
	CLD_KILLED = 2

	// CLD_DUMPED indicates that a task was killed by a signal and then dumped
	// core.
	CLD_DUMPED = 3

	// CLD_TRAPPED indicates that a task was stopped by ptrace.
	CLD_TRAPPED = 4

	// CLD_STOPPED indicates that a thread group completed a group stop.
	CLD_STOPPED = 5

	// CLD_CONTINUED indicates that a group-stopped thread group was continued.
	CLD_CONTINUED = 6

	// SYS_* codes are only meaningful for SIGSYS.

	// SYS_SECCOMP indicates that a signal originates from seccomp.
	SYS_SECCOMP = 1

	// TRAP_* codes are only meaningful for SIGTRAP.

	// TRAP_BRKPT indicates a breakpoint trap.
	TRAP_BRKPT = 1
)
