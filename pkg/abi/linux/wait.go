// Copyright 2019 The gVisor Authors.
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

package linux

import (
	"fmt"
)

// Options for waitpid(2), wait4(2), and/or waitid(2), from
// include/uapi/linux/wait.h.
const (
	WNOHANG    = 0x00000001
	WUNTRACED  = 0x00000002
	WSTOPPED   = WUNTRACED
	WEXITED    = 0x00000004
	WCONTINUED = 0x00000008
	WNOWAIT    = 0x01000000
	WNOTHREAD  = 0x20000000
	WALL       = 0x40000000
	WCLONE     = 0x80000000
)

// ID types for waitid(2), from include/uapi/linux/wait.h.
const (
	P_ALL  = 0x0
	P_PID  = 0x1
	P_PGID = 0x2
)

// WaitStatus represents a thread status, as returned by the wait* family of
// syscalls.
type WaitStatus uint32

// WaitStatusExit returns a WaitStatus representing the given exit status.
func WaitStatusExit(status int32) WaitStatus {
	return WaitStatus(uint32(status) << 8)
}

// WaitStatusTerminationSignal returns a WaitStatus representing termination by
// the given signal.
func WaitStatusTerminationSignal(sig Signal) WaitStatus {
	return WaitStatus(uint32(sig))
}

// WaitStatusStopped returns a WaitStatus representing stoppage by the given
// signal or ptrace trap code.
func WaitStatusStopped(code uint32) WaitStatus {
	return WaitStatus(code<<8 | 0x7f)
}

// WaitStatusContinued returns a WaitStatus representing continuation by
// SIGCONT.
func WaitStatusContinued() WaitStatus {
	return WaitStatus(0xffff)
}

// WithCoreDump returns a copy of ws that indicates that a core dump was
// generated.
//
// Preconditions: ws.Signaled().
func (ws WaitStatus) WithCoreDump() WaitStatus {
	return ws | 0x80
}

// Exited returns true if ws represents an exit status, consistent with
// WIFEXITED.
func (ws WaitStatus) Exited() bool {
	return ws&0x7f == 0
}

// Signaled returns true if ws represents a termination by signal, consistent
// with WIFSIGNALED.
func (ws WaitStatus) Signaled() bool {
	// ws&0x7f != 0 (exited) and ws&0x7f != 0x7f (stopped or continued)
	return ((ws&0x7f)+1)>>1 != 0
}

// CoreDumped returns true if ws indicates that a core dump was produced,
// consistent with WCOREDUMP.
//
// Preconditions: ws.Signaled().
func (ws WaitStatus) CoreDumped() bool {
	return ws&0x80 != 0
}

// Stopped returns true if ws represents a stoppage, consistent with
// WIFSTOPPED.
func (ws WaitStatus) Stopped() bool {
	return ws&0xff == 0x7f
}

// Continued returns true if ws represents a continuation by SIGCONT,
// consistent with WIFCONTINUED.
func (ws WaitStatus) Continued() bool {
	return ws == 0xffff
}

// ExitStatus returns the lower 8 bits of the exit status represented by ws,
// consistent with WEXITSTATUS.
//
// Preconditions: ws.Exited().
func (ws WaitStatus) ExitStatus() uint32 {
	return uint32((ws & 0xff00) >> 8)
}

// TerminationSignal returns the termination signal represented by ws,
// consistent with WTERMSIG.
//
// Preconditions: ws.Signaled().
func (ws WaitStatus) TerminationSignal() Signal {
	return Signal(ws & 0x7f)
}

// StopSignal returns the stop signal represented by ws, consistent with
// WSTOPSIG.
//
// Preconditions: ws.Stopped().
func (ws WaitStatus) StopSignal() Signal {
	return Signal((ws & 0xff00) >> 8)
}

// PtraceEvent returns the PTRACE_EVENT_* field in ws.
//
// Preconditions: ws.Stopped().
func (ws WaitStatus) PtraceEvent() uint32 {
	return uint32(ws >> 16)
}

// String implements fmt.Stringer.String.
func (ws WaitStatus) String() string {
	switch {
	case ws.Exited():
		return fmt.Sprintf("exit status %d", ws.ExitStatus())
	case ws.Signaled():
		if ws.CoreDumped() {
			return fmt.Sprintf("killed by signal %d (core dumped)", ws.TerminationSignal())
		}
		return fmt.Sprintf("killed by signal %d", ws.TerminationSignal())
	case ws.Stopped():
		if ev := ws.PtraceEvent(); ev != 0 {
			return fmt.Sprintf("stopped by signal %d (PTRACE_EVENT %d)", ws.StopSignal(), ev)
		}
		return fmt.Sprintf("stopped by signal %d", ws.StopSignal())
	case ws.Continued():
		return "continued"
	default:
		return fmt.Sprintf("unknown status %#x", uint32(ws))
	}
}
