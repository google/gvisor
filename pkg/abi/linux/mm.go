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

// Protections for mmap(2).
const (
	PROT_NONE      = 0
	PROT_READ      = 1 << 0
	PROT_WRITE     = 1 << 1
	PROT_EXEC      = 1 << 2
	PROT_SEM       = 1 << 3
	PROT_GROWSDOWN = 1 << 24
	PROT_GROWSUP   = 1 << 25
)

// Flags for mmap(2).
const (
	MAP_SHARED     = 1 << 0
	MAP_PRIVATE    = 1 << 1
	MAP_FIXED      = 1 << 4
	MAP_ANONYMOUS  = 1 << 5
	MAP_32BIT      = 1 << 6 // arch/x86/include/uapi/asm/mman.h
	MAP_GROWSDOWN  = 1 << 8
	MAP_DENYWRITE  = 1 << 11
	MAP_EXECUTABLE = 1 << 12
	MAP_LOCKED     = 1 << 13
	MAP_NORESERVE  = 1 << 14
	MAP_POPULATE   = 1 << 15
	MAP_NONBLOCK   = 1 << 16
	MAP_STACK      = 1 << 17
	MAP_HUGETLB    = 1 << 18
)

// Flags for mremap(2).
const (
	MREMAP_MAYMOVE = 1 << 0
	MREMAP_FIXED   = 1 << 1
)

// Flags for mlock2(2).
const (
	MLOCK_ONFAULT = 0x01
)

// Flags for mlockall(2).
const (
	MCL_CURRENT = 1
	MCL_FUTURE  = 2
	MCL_ONFAULT = 4
)

// Advice for madvise(2).
const (
	MADV_NORMAL       = 0
	MADV_RANDOM       = 1
	MADV_SEQUENTIAL   = 2
	MADV_WILLNEED     = 3
	MADV_DONTNEED     = 4
	MADV_REMOVE       = 9
	MADV_DONTFORK     = 10
	MADV_DOFORK       = 11
	MADV_MERGEABLE    = 12
	MADV_UNMERGEABLE  = 13
	MADV_HUGEPAGE     = 14
	MADV_NOHUGEPAGE   = 15
	MADV_DONTDUMP     = 16
	MADV_DODUMP       = 17
	MADV_HWPOISON     = 100
	MADV_SOFT_OFFLINE = 101
	MADV_NOMAJFAULT   = 200
	MADV_DONTCHGME    = 201
)

// Flags for msync(2).
const (
	MS_ASYNC      = 1 << 0
	MS_INVALIDATE = 1 << 1
	MS_SYNC       = 1 << 2
)

// Policies for get_mempolicy(2)/set_mempolicy(2).
const (
	MPOL_DEFAULT    = 0
	MPOL_PREFERRED  = 1
	MPOL_BIND       = 2
	MPOL_INTERLEAVE = 3
	MPOL_LOCAL      = 4
	MPOL_MAX        = 5
)

// Flags for get_mempolicy(2).
const (
	MPOL_F_NODE         = 1 << 0
	MPOL_F_ADDR         = 1 << 1
	MPOL_F_MEMS_ALLOWED = 1 << 2
)

// Flags for set_mempolicy(2).
const (
	MPOL_F_RELATIVE_NODES = 1 << 14
	MPOL_F_STATIC_NODES   = 1 << 15

	MPOL_MODE_FLAGS = (MPOL_F_STATIC_NODES | MPOL_F_RELATIVE_NODES)
)
