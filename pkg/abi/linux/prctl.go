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
	// PR_SET_PDEATHSIG will set the process' death signal.
	PR_SET_PDEATHSIG = 1

	// PR_GET_PDEATHSIG will get the process' death signal.
	PR_GET_PDEATHSIG = 2

	// PR_GET_DUMPABLE will get the process's dumpable flag.
	PR_GET_DUMPABLE = 3

	// PR_SET_DUMPABLE will set the process's dumpable flag.
	PR_SET_DUMPABLE = 4

	// PR_GET_KEEPCAPS will get the value of the keep capabilities flag.
	PR_GET_KEEPCAPS = 7

	// PR_SET_KEEPCAPS will set the value of the keep capabilities flag.
	PR_SET_KEEPCAPS = 8

	// PR_GET_TIMING will get the process's timing method.
	PR_GET_TIMING = 13

	// PR_SET_TIMING will set the process's timing method.
	PR_SET_TIMING = 14

	// PR_SET_NAME will set the process' name.
	PR_SET_NAME = 15

	// PR_GET_NAME will get the process' name.
	PR_GET_NAME = 16

	// PR_GET_SECCOMP will get a process' seccomp mode.
	PR_GET_SECCOMP = 21

	// PR_SET_SECCOMP will set a process' seccomp mode.
	PR_SET_SECCOMP = 22

	// PR_CAPBSET_READ will get the capability bounding set.
	PR_CAPBSET_READ = 23

	// PR_CAPBSET_DROP will set the capability bounding set.
	PR_CAPBSET_DROP = 24

	// PR_GET_TSC will get the the value of the flag determining whether the
	// timestamp counter can be read.
	PR_GET_TSC = 25

	// PR_SET_TSC will set the the value of the flag determining whether the
	// timestamp counter can be read.
	PR_SET_TSC = 26

	// PR_SET_TIMERSLACK set the process's time slack.
	PR_SET_TIMERSLACK = 29

	// PR_GET_TIMERSLACK get the process's time slack.
	PR_GET_TIMERSLACK = 30

	// PR_TASK_PERF_EVENTS_DISABLE disable all performance counters attached to
	// the calling process.
	PR_TASK_PERF_EVENTS_DISABLE = 31

	// PR_TASK_PERF_EVENTS_ENABLE enable all performance counters attached to
	// the calling process.
	PR_TASK_PERF_EVENTS_ENABLE = 32

	// PR_MCE_KILL set the machine check memory corruption kill policy for the
	// calling thread.
	PR_MCE_KILL = 33

	// PR_MCE_KILL_GET get the machine check memory corruption kill policy for the
	// calling thread.
	PR_MCE_KILL_GET = 34

	// PR_SET_MM will modify certain kernel memory map descriptor fields of the
	// calling process. See prctl(2) for more information.
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
	// PR_SET_MM_EXE_FILE will supersede the /proc/pid/exe symbolic link with a
	// new one pointing to a new executable file identified by the file descriptor
	// provided in arg3 argument. See prctl(2) for more information.
	PR_SET_MM_EXE_FILE = 13
	PR_SET_MM_MAP      = 14
	PR_SET_MM_MAP_SIZE = 15

	// PR_SET_CHILD_SUBREAPER set the "child subreaper" attribute of the calling
	// process.
	PR_SET_CHILD_SUBREAPER = 36

	// PR_GET_CHILD_SUBREAPER get the "child subreaper" attribute of the calling
	// process.
	PR_GET_CHILD_SUBREAPER = 37

	// PR_SET_NO_NEW_PRIVS will set the calling thread's no_new_privs bit.
	PR_SET_NO_NEW_PRIVS = 38

	// PR_GET_NO_NEW_PRIVS will get the calling thread's no_new_privs bit.
	PR_GET_NO_NEW_PRIVS = 39

	// PR_GET_TID_ADDRESS retrieve the clear_child_tid address.
	PR_GET_TID_ADDRESS = 40

	// PR_SET_THP_DISABLE set the state of the "THP disable" flag for the calling
	// thread.
	PR_SET_THP_DISABLE = 41

	// PR_GET_THP_DISABLE get the state of the "THP disable" flag for the calling
	// thread.
	PR_GET_THP_DISABLE = 42

	// PR_MPX_ENABLE_MANAGEMENT enable kernel management of Memory Protection
	// eXtensions (MPX) bounds tables.
	PR_MPX_ENABLE_MANAGEMENT = 43

	// PR_MPX_DISABLE_MANAGEMENTdisable kernel management of Memory Protection
	// eXtensions (MPX) bounds tables.
	PR_MPX_DISABLE_MANAGEMENT = 44
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
