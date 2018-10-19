// Copyright 2018 Google LLC
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

	// PR_GET_KEEPCAPS will get the value of the keep capabilities flag.
	PR_GET_KEEPCAPS = 7

	// PR_SET_KEEPCAPS will set the value of the keep capabilities flag.
	PR_SET_KEEPCAPS = 8

	// PR_SET_NAME will set the process' name.
	PR_SET_NAME = 15

	// PR_GET_NAME will get the process' name.
	PR_GET_NAME = 16

	// PR_SET_MM will modify certain kernel memory map descriptor fields of the
	// calling process. See prctl(2) for more information.
	PR_SET_MM = 35

	// PR_SET_MM_EXE_FILE will supersede the /proc/pid/exe symbolic link with a
	// new one pointing to a new executable file identified by the file descriptor
	// provided in arg3 argument. See prctl(2) for more information.
	PR_SET_MM_EXE_FILE = 13

	// PR_SET_NO_NEW_PRIVS will set the calling thread's no_new_privs bit.
	PR_SET_NO_NEW_PRIVS = 38

	// PR_GET_NO_NEW_PRIVS will get the calling thread's no_new_privs bit.
	PR_GET_NO_NEW_PRIVS = 39

	// PR_SET_SECCOMP will set a process' seccomp mode.
	PR_SET_SECCOMP = 22

	// PR_GET_SECCOMP will get a process' seccomp mode.
	PR_GET_SECCOMP = 21

	// PR_CAPBSET_READ will get the capability bounding set.
	PR_CAPBSET_READ = 23

	// PR_CAPBSET_DROP will set the capability bounding set.
	PR_CAPBSET_DROP = 24
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
