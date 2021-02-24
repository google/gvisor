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

// PR_* flags, from <linux/pcrtl.h> for prctl(2).
const (
	// PR_SET_PDEATHSIG sets the process' death signal.
	PR_SET_PDEATHSIG = 1

	// PR_GET_PDEATHSIG gets the process' death signal.
	PR_GET_PDEATHSIG = 2

	// PR_GET_DUMPABLE gets the process' dumpable flag.
	PR_GET_DUMPABLE = 3

	// PR_SET_DUMPABLE sets the process' dumpable flag.
	PR_SET_DUMPABLE = 4

	// PR_GET_KEEPCAPS gets the value of the keep capabilities flag.
	PR_GET_KEEPCAPS = 7

	// PR_SET_KEEPCAPS sets the value of the keep capabilities flag.
	PR_SET_KEEPCAPS = 8

	// PR_GET_TIMING gets the process' timing method.
	PR_GET_TIMING = 13

	// PR_SET_TIMING sets the process' timing method.
	PR_SET_TIMING = 14

	// PR_SET_NAME sets the process' name.
	PR_SET_NAME = 15

	// PR_GET_NAME gets the process' name.
	PR_GET_NAME = 16

	// PR_GET_SECCOMP gets a process' seccomp mode.
	PR_GET_SECCOMP = 21

	// PR_SET_SECCOMP sets a process' seccomp mode.
	PR_SET_SECCOMP = 22

	// PR_CAPBSET_READ gets the capability bounding set.
	PR_CAPBSET_READ = 23

	// PR_CAPBSET_DROP sets the capability bounding set.
	PR_CAPBSET_DROP = 24

	// PR_GET_TSC gets the value of the flag determining whether the
	// timestamp counter can be read.
	PR_GET_TSC = 25

	// PR_SET_TSC sets the value of the flag determining whether the
	// timestamp counter can be read.
	PR_SET_TSC = 26

	// PR_SET_TIMERSLACK sets the process' time slack.
	PR_SET_TIMERSLACK = 29

	// PR_GET_TIMERSLACK gets the process' time slack.
	PR_GET_TIMERSLACK = 30

	// PR_TASK_PERF_EVENTS_DISABLE disables all performance counters
	// attached to the calling process.
	PR_TASK_PERF_EVENTS_DISABLE = 31

	// PR_TASK_PERF_EVENTS_ENABLE enables all performance counters attached
	// to the calling process.
	PR_TASK_PERF_EVENTS_ENABLE = 32

	// PR_MCE_KILL sets the machine check memory corruption kill policy for
	// the calling thread.
	PR_MCE_KILL = 33

	// PR_MCE_KILL_GET gets the machine check memory corruption kill policy
	// for the calling thread.
	PR_MCE_KILL_GET = 34

	// PR_SET_MM modifies certain kernel memory map descriptor fields of
	// the calling process. See prctl(2) for more information.
	PR_SET_MM = 35

	PR_SET_MM_START_CODE  = 1
	PR_SET_MM_END_CODE    = 2
	PR_SET_MM_START_DATA  = 3
	PR_SET_MM_END_DATA    = 4
	PR_SET_MM_START_STACK = 5
	PR_SET_MM_START_BRK   = 6
	PR_SET_MM_BRK         = 7
	PR_SET_MM_ARG_START   = 8
	PR_SET_MM_ARG_END     = 9
	PR_SET_MM_ENV_START   = 10
	PR_SET_MM_ENV_END     = 11
	PR_SET_MM_AUXV        = 12
	// PR_SET_MM_EXE_FILE supersedes the /proc/pid/exe symbolic link with a
	// new one pointing to a new executable file identified by the file
	// descriptor provided in arg3 argument. See prctl(2) for more
	// information.
	PR_SET_MM_EXE_FILE = 13
	PR_SET_MM_MAP      = 14
	PR_SET_MM_MAP_SIZE = 15

	// PR_SET_CHILD_SUBREAPER sets the "child subreaper" attribute of the
	// calling process.
	PR_SET_CHILD_SUBREAPER = 36

	// PR_GET_CHILD_SUBREAPER gets the "child subreaper" attribute of the
	// calling process.
	PR_GET_CHILD_SUBREAPER = 37

	// PR_SET_NO_NEW_PRIVS sets the calling thread's no_new_privs bit.
	PR_SET_NO_NEW_PRIVS = 38

	// PR_GET_NO_NEW_PRIVS gets the calling thread's no_new_privs bit.
	PR_GET_NO_NEW_PRIVS = 39

	// PR_GET_TID_ADDRESS retrieves the clear_child_tid address.
	PR_GET_TID_ADDRESS = 40

	// PR_SET_THP_DISABLE sets the state of the "THP disable" flag for the
	// calling thread.
	PR_SET_THP_DISABLE = 41

	// PR_GET_THP_DISABLE gets the state of the "THP disable" flag for the
	// calling thread.
	PR_GET_THP_DISABLE = 42

	// PR_MPX_ENABLE_MANAGEMENT enables kernel management of Memory
	// Protection eXtensions (MPX) bounds tables.
	PR_MPX_ENABLE_MANAGEMENT = 43

	// PR_MPX_DISABLE_MANAGEMENT disables kernel management of Memory
	// Protection eXtensions (MPX) bounds tables.
	PR_MPX_DISABLE_MANAGEMENT = 44

	// PR_SET_PTRACER allows a specific process (or any, if PR_SET_PTRACER_ANY is
	// specified) to ptrace the current task.
	PR_SET_PTRACER     = 0x59616d61
	PR_SET_PTRACER_ANY = -1
)

// From <asm/prctl.h>
// Flags are used in syscall arch_prctl(2).
const (
	ARCH_SET_GS    = 0x1001
	ARCH_SET_FS    = 0x1002
	ARCH_GET_FS    = 0x1003
	ARCH_GET_GS    = 0x1004
	ARCH_SET_CPUID = 0x1012
)

// Flags for prctl(PR_SET_DUMPABLE), defined in include/linux/sched/coredump.h.
const (
	SUID_DUMP_DISABLE = 0
	SUID_DUMP_USER    = 1
	SUID_DUMP_ROOT    = 2
)
