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

// ELF ET_CORE and ptrace GETREGSET/SETREGSET register set types.
//
// See include/uapi/linux/elf.h.
const (
	// NT_PRSTATUS is for general purpose register.
	NT_PRSTATUS = 0x1

	// NT_PRFPREG is for float point register.
	NT_PRFPREG = 0x2

	// NT_X86_XSTATE is for x86 extended state using xsave.
	NT_X86_XSTATE = 0x202

	// NT_ARM_TLS is for ARM TLS register.
	NT_ARM_TLS = 0x401
)

// ElfHeader64 is the ELF64 file header.
//
// +marshal
type ElfHeader64 struct {
	Ident     [16]byte // File identification.
	Type      uint16   // File type.
	Machine   uint16   // Machine architecture.
	Version   uint32   // ELF format version.
	Entry     uint64   // Entry point.
	Phoff     uint64   // Program header file offset.
	Shoff     uint64   // Section header file offset.
	Flags     uint32   // Architecture-specific flags.
	Ehsize    uint16   // Size of ELF header in bytes.
	Phentsize uint16   // Size of program header entry.
	Phnum     uint16   // Number of program header entries.
	Shentsize uint16   // Size of section header entry.
	Shnum     uint16   // Number of section header entries.
	Shstrndx  uint16   // Section name strings section.
}

// ElfSection64 is the ELF64 Section header.
//
// +marshal
type ElfSection64 struct {
	Name      uint32 // Section name (index into the section header string table).
	Type      uint32 // Section type.
	Flags     uint64 // Section flags.
	Addr      uint64 // Address in memory image.
	Off       uint64 // Offset in file.
	Size      uint64 // Size in bytes.
	Link      uint32 // Index of a related section.
	Info      uint32 // Depends on section type.
	Addralign uint64 // Alignment in bytes.
	Entsize   uint64 // Size of each entry in section.
}

// ElfProg64 is the ELF64 Program header.
//
// +marshal
type ElfProg64 struct {
	Type   uint32 // Entry type.
	Flags  uint32 // Access permission flags.
	Off    uint64 // File offset of contents.
	Vaddr  uint64 // Virtual address in memory image.
	Paddr  uint64 // Physical address (not used).
	Filesz uint64 // Size of contents in file.
	Memsz  uint64 // Size of contents in memory.
	Align  uint64 // Alignment in memory and file.
}
