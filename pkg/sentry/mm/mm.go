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

// Package mm provides a memory management subsystem. See README.md for a
// detailed overview.
//
// Lock order:
//
// fs locks, except for memmap.Mappable locks
//   mm.MemoryManager.metadataMu
//     mm.MemoryManager.mappingMu
//       Locks taken by memmap.Mappable methods other than Translate
//         mm.MemoryManager.activeMu
//           Locks taken by memmap.Mappable.Translate
//             mm.privateRefs.mu
//               platform.File locks
//         mm.aioManager.mu
//           mm.AIOContext.mu
//
// Only mm.MemoryManager.Fork is permitted to lock mm.MemoryManager.activeMu in
// multiple mm.MemoryManagers, as it does so in a well-defined order (forked
// child first).
package mm

import (
	"sync"

	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/memmap"
	"gvisor.googlesource.com/gvisor/pkg/sentry/platform"
	"gvisor.googlesource.com/gvisor/pkg/sentry/safemem"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	ssync "gvisor.googlesource.com/gvisor/pkg/sync"
)

// MemoryManager implements a virtual address space.
//
// +stateify savable
type MemoryManager struct {
	// p is the platform.
	//
	// p is immutable.
	p platform.Platform

	// haveASIO is the cached result of p.SupportsAddressSpaceIO(). Aside from
	// eliminating an indirect call in the hot I/O path, this makes
	// MemoryManager.asioEnabled() a leaf function, allowing it to be inlined.
	//
	// haveASIO is immutable.
	haveASIO bool `state:"nosave"`

	// layout is the memory layout.
	//
	// layout is set by the binary loader before the MemoryManager can be used.
	layout arch.MmapLayout

	// privateRefs stores reference counts for private memory (memory whose
	// ownership is shared by one or more pmas instead of being owned by a
	// memmap.Mappable).
	//
	// NOTE: This should be replaced using refcounts on
	// platform.File.
	//
	// privateRefs is immutable.
	privateRefs *privateRefs

	// users is the number of dependences on the mappings in the MemoryManager.
	// When the number of references in users reaches zero, all mappings are
	// unmapped.
	//
	// users is accessed using atomic memory operations.
	users int32

	// mappingMu is analogous to Linux's struct mm_struct::mmap_sem.
	mappingMu ssync.DowngradableRWMutex `state:"nosave"`

	// vmas stores virtual memory areas. Since vmas are stored by value,
	// clients should usually use vmaIterator.ValuePtr() instead of
	// vmaIterator.Value() to get a pointer to the vma rather than a copy.
	//
	// Invariants: vmas are always page-aligned.
	//
	// vmas is protected by mappingMu.
	vmas vmaSet

	// usageAS is vmas.Span(), cached to accelerate RLIMIT_AS checks.
	//
	// usageAS is protected by mappingMu.
	usageAS uint64

	// brk is the mm's brk, which is manipulated using the brk(2) system call.
	// The brk is initially set up by the loader which maps an executable
	// binary into the mm.
	//
	// brk is protected by mappingMu.
	brk usermem.AddrRange

	// activeMu is loosely analogous to Linux's struct
	// mm_struct::page_table_lock.
	activeMu ssync.DowngradableRWMutex `state:"nosave"`

	// pmas stores platform mapping areas used to implement vmas. Since pmas
	// are stored by value, clients should usually use pmaIterator.ValuePtr()
	// instead of pmaIterator.Value() to get a pointer to the pma rather than
	// a copy.
	//
	// Inserting or removing segments from pmas should happen along with a
	// call to mm.insertRSS or mm.removeRSS.
	//
	// Invariants: pmas are always page-aligned. If a pma exists for a given
	// address, a vma must also exist for that address.
	//
	// pmas is protected by activeMu.
	pmas pmaSet

	// curRSS is pmas.Span(), cached to accelerate updates to maxRSS. It is
	// reported as the MemoryManager's RSS.
	//
	// maxRSS should be modified only via insertRSS and removeRSS, not
	// directly.
	//
	// maxRSS is protected by activeMu.
	curRSS uint64

	// maxRSS is the maximum resident set size in bytes of a MemoryManager.
	// It is tracked as the application adds and removes mappings to pmas.
	//
	// maxRSS should be modified only via insertRSS, not directly.
	//
	// maxRSS is protected by activeMu.
	maxRSS uint64

	// as is the platform.AddressSpace that pmas are mapped into. active is the
	// number of contexts that require as to be non-nil; if active == 0, as may
	// be nil.
	//
	// as is protected by activeMu. active is manipulated with atomic memory
	// operations; transitions to and from zero are additionally protected by
	// activeMu. (This is because such transitions may need to be atomic with
	// changes to as.)
	as     platform.AddressSpace `state:"nosave"`
	active int32                 `state:"zerovalue"`

	// unmapAllOnActivate indicates that the next Activate call should activate
	// an empty AddressSpace.
	//
	// This is used to ensure that an AddressSpace cached in
	// NewAddressSpace is not used after some change in the MemoryManager
	// or VMAs has made that AddressSpace stale.
	//
	// unmapAllOnActivate is protected by activeMu. It must only be set when
	// there is no active or cached AddressSpace. If as != nil, then
	// invalidations should be propagated immediately.
	unmapAllOnActivate bool `state:"nosave"`

	// If captureInvalidations is true, calls to MM.Invalidate() are recorded
	// in capturedInvalidations rather than being applied immediately to pmas.
	// This is to avoid a race condition in MM.Fork(); see that function for
	// details.
	//
	// Both captureInvalidations and capturedInvalidations are protected by
	// activeMu. Neither need to be saved since captureInvalidations is only
	// enabled during MM.Fork(), during which saving can't occur.
	captureInvalidations  bool             `state:"zerovalue"`
	capturedInvalidations []invalidateArgs `state:"nosave"`

	metadataMu sync.Mutex `state:"nosave"`

	// argv is the application argv. This is set up by the loader and may be
	// modified by prctl(PR_SET_MM_ARG_START/PR_SET_MM_ARG_END). No
	// requirements apply to argv; we do not require that argv.WellFormed().
	//
	// argv is protected by metadataMu.
	argv usermem.AddrRange

	// envv is the application envv. This is set up by the loader and may be
	// modified by prctl(PR_SET_MM_ENV_START/PR_SET_MM_ENV_END). No
	// requirements apply to envv; we do not require that envv.WellFormed().
	//
	// envv is protected by metadataMu.
	envv usermem.AddrRange

	// auxv is the ELF's auxiliary vector.
	//
	// auxv is protected by metadataMu.
	auxv arch.Auxv

	// executable is the executable for this MemoryManager. If executable
	// is not nil, it holds a reference on the Dirent.
	//
	// executable is protected by metadataMu.
	executable *fs.Dirent

	// aioManager keeps track of AIOContexts used for async IOs. AIOManager
	// must be cloned when CLONE_VM is used.
	aioManager aioManager
}

// vma represents a virtual memory area.
//
// +stateify savable
type vma struct {
	// mappable is the virtual memory object mapped by this vma. If mappable is
	// nil, the vma represents a private anonymous mapping.
	mappable memmap.Mappable

	// off is the offset into mappable at which this vma begins. If mappable is
	// nil, off is meaningless.
	off uint64

	// To speedup VMA save/restore, we group and save the following booleans
	// as a single integer.

	// realPerms are the memory permissions on this vma, as defined by the
	// application.
	realPerms usermem.AccessType `state:".(int)"`

	// effectivePerms are the memory permissions on this vma which are
	// actually used to control access.
	//
	// Invariant: effectivePerms == realPerms.Effective().
	effectivePerms usermem.AccessType `state:"manual"`

	// maxPerms limits the set of permissions that may ever apply to this
	// memory, as well as accesses for which usermem.IOOpts.IgnorePermissions
	// is true (e.g. ptrace(PTRACE_POKEDATA)).
	//
	// Invariant: maxPerms == maxPerms.Effective().
	maxPerms usermem.AccessType `state:"manual"`

	// private is true if this is a MAP_PRIVATE mapping, such that writes to
	// the mapping are propagated to a copy.
	private bool `state:"manual"`

	// growsDown is true if the mapping may be automatically extended downward
	// under certain conditions. If growsDown is true, mappable must be nil.
	//
	// There is currently no corresponding growsUp flag; in Linux, the only
	// architectures that can have VM_GROWSUP mappings are ia64, parisc, and
	// metag, none of which we currently support.
	growsDown bool `state:"manual"`

	// If id is not nil, it controls the lifecycle of mappable and provides vma
	// metadata shown in /proc/[pid]/maps, and the vma holds a reference.
	id memmap.MappingIdentity

	// If hint is non-empty, it is a description of the vma printed in
	// /proc/[pid]/maps. hint takes priority over id.MappedName().
	hint string
}

const (
	vmaRealPermsRead = 1 << iota
	vmaRealPermsWrite
	vmaRealPermsExecute
	vmaEffectivePermsRead
	vmaEffectivePermsWrite
	vmaEffectivePermsExecute
	vmaMaxPermsRead
	vmaMaxPermsWrite
	vmaMaxPermsExecute
	vmaPrivate
	vmaGrowsDown
)

func (v *vma) saveRealPerms() int {
	var b int
	if v.realPerms.Read {
		b |= vmaRealPermsRead
	}
	if v.realPerms.Write {
		b |= vmaRealPermsWrite
	}
	if v.realPerms.Execute {
		b |= vmaRealPermsExecute
	}
	if v.effectivePerms.Read {
		b |= vmaEffectivePermsRead
	}
	if v.effectivePerms.Write {
		b |= vmaEffectivePermsWrite
	}
	if v.effectivePerms.Execute {
		b |= vmaEffectivePermsExecute
	}
	if v.maxPerms.Read {
		b |= vmaMaxPermsRead
	}
	if v.maxPerms.Write {
		b |= vmaMaxPermsWrite
	}
	if v.maxPerms.Execute {
		b |= vmaMaxPermsExecute
	}
	if v.private {
		b |= vmaPrivate
	}
	if v.growsDown {
		b |= vmaGrowsDown
	}
	return b
}

func (v *vma) loadRealPerms(b int) {
	if b&vmaRealPermsRead > 0 {
		v.realPerms.Read = true
	}
	if b&vmaRealPermsWrite > 0 {
		v.realPerms.Write = true
	}
	if b&vmaRealPermsExecute > 0 {
		v.realPerms.Execute = true
	}
	if b&vmaEffectivePermsRead > 0 {
		v.effectivePerms.Read = true
	}
	if b&vmaEffectivePermsWrite > 0 {
		v.effectivePerms.Write = true
	}
	if b&vmaEffectivePermsExecute > 0 {
		v.effectivePerms.Execute = true
	}
	if b&vmaMaxPermsRead > 0 {
		v.maxPerms.Read = true
	}
	if b&vmaMaxPermsWrite > 0 {
		v.maxPerms.Write = true
	}
	if b&vmaMaxPermsExecute > 0 {
		v.maxPerms.Execute = true
	}
	if b&vmaPrivate > 0 {
		v.private = true
	}
	if b&vmaGrowsDown > 0 {
		v.growsDown = true
	}
}

func (v *vma) isMappableAsWritable() bool {
	return !v.private && v.maxPerms.Write
}

// pma represents a platform mapping area.
//
// +stateify savable
type pma struct {
	// file is the file mapped by this pma. Only pmas for which file ==
	// platform.Platform.Memory() may be saved. pmas hold a reference to the
	// corresponding file range while they exist.
	file platform.File `state:"nosave"`

	// off is the offset into file at which this pma begins.
	off uint64

	// vmaEffectivePerms and vmaMaxPerms are duplicated from the
	// corresponding vma so that the IO implementation can avoid iterating
	// mm.vmas when pmas already exist.
	vmaEffectivePerms usermem.AccessType
	vmaMaxPerms       usermem.AccessType

	// needCOW is true if writes to the mapping must be propagated to a copy.
	needCOW bool

	// private is true if this pma represents private memory.
	//
	// If private is true, file must be platform.Platform.Memory(), the pma
	// holds a reference on the mapped memory that is tracked in privateRefs,
	// and calls to Invalidate for which
	// memmap.InvalidateOpts.InvalidatePrivate is false should ignore the pma.
	//
	// If private is false, this pma caches a translation from the
	// corresponding vma's memmap.Mappable.Translate.
	private bool

	// If internalMappings is not empty, it is the cached return value of
	// file.MapInternal for the platform.FileRange mapped by this pma.
	internalMappings safemem.BlockSeq `state:"nosave"`
}

// +stateify savable
type privateRefs struct {
	mu sync.Mutex `state:"nosave"`

	// refs maps offsets into Platform.Memory() to the number of pmas (or,
	// equivalently, MemoryManagers) that share ownership of the memory at that
	// offset.
	refs fileRefcountSet
}

type invalidateArgs struct {
	ar   usermem.AddrRange
	opts memmap.InvalidateOpts
}

// fileRefcountSetFunctions implements segment.Functions for fileRefcountSet.
type fileRefcountSetFunctions struct{}

func (fileRefcountSetFunctions) MinKey() uint64 {
	return 0
}

func (fileRefcountSetFunctions) MaxKey() uint64 {
	return ^uint64(0)
}

func (fileRefcountSetFunctions) ClearValue(_ *int32) {
}

func (fileRefcountSetFunctions) Merge(_ platform.FileRange, rc1 int32, _ platform.FileRange, rc2 int32) (int32, bool) {
	return rc1, rc1 == rc2
}

func (fileRefcountSetFunctions) Split(_ platform.FileRange, rc int32, _ uint64) (int32, int32) {
	return rc, rc
}
