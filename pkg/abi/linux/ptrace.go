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

package linux

// ptrace commands from include/uapi/linux/ptrace.h.
const (
	PTRACE_TRACEME              = 0
	PTRACE_PEEKTEXT             = 1
	PTRACE_PEEKDATA             = 2
	PTRACE_PEEKUSR              = 3
	PTRACE_POKETEXT             = 4
	PTRACE_POKEDATA             = 5
	PTRACE_POKEUSR              = 6
	PTRACE_CONT                 = 7
	PTRACE_KILL                 = 8
	PTRACE_SINGLESTEP           = 9
	PTRACE_ATTACH               = 16
	PTRACE_DETACH               = 17
	PTRACE_SYSCALL              = 24
	PTRACE_SETOPTIONS           = 0x4200
	PTRACE_GETEVENTMSG          = 0x4201
	PTRACE_GETSIGINFO           = 0x4202
	PTRACE_SETSIGINFO           = 0x4203
	PTRACE_GETREGSET            = 0x4204
	PTRACE_SETREGSET            = 0x4205
	PTRACE_SEIZE                = 0x4206
	PTRACE_INTERRUPT            = 0x4207
	PTRACE_LISTEN               = 0x4208
	PTRACE_PEEKSIGINFO          = 0x4209
	PTRACE_GETSIGMASK           = 0x420a
	PTRACE_SETSIGMASK           = 0x420b
	PTRACE_SECCOMP_GET_FILTER   = 0x420c
	PTRACE_SECCOMP_GET_METADATA = 0x420d
)

// ptrace commands from arch/x86/include/uapi/asm/ptrace-abi.h.
const (
	PTRACE_GETREGS           = 12
	PTRACE_SETREGS           = 13
	PTRACE_GETFPREGS         = 14
	PTRACE_SETFPREGS         = 15
	PTRACE_GETFPXREGS        = 18
	PTRACE_SETFPXREGS        = 19
	PTRACE_OLDSETOPTIONS     = 21
	PTRACE_GET_THREAD_AREA   = 25
	PTRACE_SET_THREAD_AREA   = 26
	PTRACE_ARCH_PRCTL        = 30
	PTRACE_SYSEMU            = 31
	PTRACE_SYSEMU_SINGLESTEP = 32
	PTRACE_SINGLEBLOCK       = 33
)

// ptrace event codes from include/uapi/linux/ptrace.h.
const (
	PTRACE_EVENT_FORK       = 1
	PTRACE_EVENT_VFORK      = 2
	PTRACE_EVENT_CLONE      = 3
	PTRACE_EVENT_EXEC       = 4
	PTRACE_EVENT_VFORK_DONE = 5
	PTRACE_EVENT_EXIT       = 6
	PTRACE_EVENT_SECCOMP    = 7
	PTRACE_EVENT_STOP       = 128
)

// PTRACE_SETOPTIONS options from include/uapi/linux/ptrace.h.
const (
	PTRACE_O_TRACESYSGOOD    = 1
	PTRACE_O_TRACEFORK       = 1 << PTRACE_EVENT_FORK
	PTRACE_O_TRACEVFORK      = 1 << PTRACE_EVENT_VFORK
	PTRACE_O_TRACECLONE      = 1 << PTRACE_EVENT_CLONE
	PTRACE_O_TRACEEXEC       = 1 << PTRACE_EVENT_EXEC
	PTRACE_O_TRACEVFORKDONE  = 1 << PTRACE_EVENT_VFORK_DONE
	PTRACE_O_TRACEEXIT       = 1 << PTRACE_EVENT_EXIT
	PTRACE_O_TRACESECCOMP    = 1 << PTRACE_EVENT_SECCOMP
	PTRACE_O_EXITKILL        = 1 << 20
	PTRACE_O_SUSPEND_SECCOMP = 1 << 21
)

// YAMA ptrace_scope levels from security/yama/yama_lsm.c.
const (
	YAMA_SCOPE_DISABLED   = 0
	YAMA_SCOPE_RELATIONAL = 1
)
