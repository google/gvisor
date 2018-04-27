// Copyright 2018 Google Inc.
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

// Linux auxiliary vector entry types.
const (
	// AT_NULL is the end of the auxiliary vector.
	AT_NULL = 0

	// AT_IGNORE should be ignored.
	AT_IGNORE = 1

	// AT_EXECFD is the file descriptor of the program.
	AT_EXECFD = 2

	// AT_PHDR points to the program headers.
	AT_PHDR = 3

	// AT_PHENT is the size of a program header entry.
	AT_PHENT = 4

	// AT_PHNUM is the number of program headers.
	AT_PHNUM = 5

	// AT_PAGESZ is the system page size.
	AT_PAGESZ = 6

	// AT_BASE is the base address of the interpreter.
	AT_BASE = 7

	// AT_FLAGS are flags.
	AT_FLAGS = 8

	// AT_ENTRY is the program entry point.
	AT_ENTRY = 9

	// AT_NOTELF indicates that the program is not an ELF binary.
	AT_NOTELF = 10

	// AT_UID is the real UID.
	AT_UID = 11

	// AT_EUID is the effective UID.
	AT_EUID = 12

	// AT_GID is the real GID.
	AT_GID = 13

	// AT_EGID is the effective GID.
	AT_EGID = 14

	// AT_PLATFORM is a string identifying the CPU.
	AT_PLATFORM = 15

	// AT_HWCAP are arch-dependent CPU capabilities.
	AT_HWCAP = 16

	// AT_CLKTCK is the frequency used by times(2).
	AT_CLKTCK = 17

	// AT_SECURE indicate secure mode.
	AT_SECURE = 23

	// AT_BASE_PLATFORM is a string identifying the "real" platform. It may
	// differ from AT_PLATFORM.
	AT_BASE_PLATFORM = 24

	// AT_RANDOM points to 16-bytes of random data.
	AT_RANDOM = 25

	// AT_HWCAP2 is an extension of AT_HWCAP.
	AT_HWCAP2 = 26

	// AT_EXECFN is the path used to execute the program.
	AT_EXECFN = 31

	// AT_SYSINFO_EHDR is the address of the VDSO.
	AT_SYSINFO_EHDR = 33
)
