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

// Package memmap defines semantics for memory mappings.
package memmap

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/safemem"
)

// Mappable represents a memory-mappable object, a mutable mapping from uint64
// offsets to (File, uint64 File offset) pairs.
//
// See mm/mm.go for Mappable's place in the lock order.
//
// All Mappable methods have the following preconditions:
// * hostarch.AddrRanges and MappableRanges must be non-empty (Length() != 0).
// * hostarch.Addrs and Mappable offsets must be page-aligned.
type Mappable interface {
	// AddMapping notifies the Mappable of a mapping from addresses ar in ms to
	// offsets [offset, offset+ar.Length()) in this Mappable.
	//
	// The writable flag indicates whether the backing data for a Mappable can
	// be modified through the mapping. Effectively, this means a shared mapping
	// where Translate may be called with at.Write == true. This is a property
	// established at mapping creation and must remain constant throughout the
	// lifetime of the mapping.
	//
	// Preconditions: offset+ar.Length() does not overflow.
	AddMapping(ctx context.Context, ms MappingSpace, ar hostarch.AddrRange, offset uint64, writable bool) error

	// RemoveMapping notifies the Mappable of the removal of a mapping from
	// addresses ar in ms to offsets [offset, offset+ar.Length()) in this
	// Mappable.
	//
	// Preconditions:
	// * offset+ar.Length() does not overflow.
	// * The removed mapping must exist. writable must match the
	//   corresponding call to AddMapping.
	RemoveMapping(ctx context.Context, ms MappingSpace, ar hostarch.AddrRange, offset uint64, writable bool)

	// CopyMapping notifies the Mappable of an attempt to copy a mapping in ms
	// from srcAR to dstAR. For most Mappables, this is equivalent to
	// AddMapping. Note that it is possible that srcAR.Length() != dstAR.Length(),
	// and also that srcAR.Length() == 0.
	//
	// CopyMapping is only called when a mapping is copied within a given
	// MappingSpace; it is analogous to Linux's vm_operations_struct::mremap.
	//
	// Preconditions:
	// * offset+srcAR.Length() and offset+dstAR.Length() do not overflow.
	// * The mapping at srcAR must exist. writable must match the
	//   corresponding call to AddMapping.
	CopyMapping(ctx context.Context, ms MappingSpace, srcAR, dstAR hostarch.AddrRange, offset uint64, writable bool) error

	// Translate returns the Mappable's current mappings for at least the range
	// of offsets specified by required, and at most the range of offsets
	// specified by optional. at is the set of access types that may be
	// performed using the returned Translations. If not all required offsets
	// are translated, it returns a non-nil error explaining why.
	//
	// Translations are valid until invalidated by a callback to
	// MappingSpace.Invalidate or until the caller removes its mapping of the
	// translated range. Mappable implementations must ensure that at least one
	// reference is held on all pages in a File that may be the result
	// of a valid Translation.
	//
	// Preconditions:
	// * required.Length() > 0.
	// * optional.IsSupersetOf(required).
	// * required and optional must be page-aligned.
	// * The caller must have established a mapping for all of the queried
	//   offsets via a previous call to AddMapping.
	// * The caller is responsible for ensuring that calls to Translate
	//   synchronize with invalidation.
	//
	// Postconditions: See CheckTranslateResult.
	Translate(ctx context.Context, required, optional MappableRange, at hostarch.AccessType) ([]Translation, error)

	// InvalidateUnsavable requests that the Mappable invalidate Translations
	// that cannot be preserved across save/restore.
	//
	// Invariant: InvalidateUnsavable never races with concurrent calls to any
	// other Mappable methods.
	InvalidateUnsavable(ctx context.Context) error
}

// Translations are returned by Mappable.Translate.
type Translation struct {
	// Source is the translated range in the Mappable.
	Source MappableRange

	// File is the mapped file.
	File File

	// Offset is the offset into File at which this Translation begins.
	Offset uint64

	// Perms is the set of permissions for which platform.AddressSpace.MapFile
	// and platform.AddressSpace.MapInternal on this Translation is permitted.
	Perms hostarch.AccessType
}

// FileRange returns the FileRange represented by t.
func (t Translation) FileRange() FileRange {
	return FileRange{t.Offset, t.Offset + t.Source.Length()}
}

// CheckTranslateResult returns an error if (ts, terr) does not satisfy all
// postconditions for Mappable.Translate(required, optional, at).
//
// Preconditions: Same as Mappable.Translate.
func CheckTranslateResult(required, optional MappableRange, at hostarch.AccessType, ts []Translation, terr error) error {
	// Verify that the inputs to Mappable.Translate were valid.
	if !required.WellFormed() || required.Length() == 0 {
		panic(fmt.Sprintf("invalid required range: %v", required))
	}
	if !hostarch.Addr(required.Start).IsPageAligned() || !hostarch.Addr(required.End).IsPageAligned() {
		panic(fmt.Sprintf("unaligned required range: %v", required))
	}
	if !optional.IsSupersetOf(required) {
		panic(fmt.Sprintf("optional range %v is not a superset of required range %v", optional, required))
	}
	if !hostarch.Addr(optional.Start).IsPageAligned() || !hostarch.Addr(optional.End).IsPageAligned() {
		panic(fmt.Sprintf("unaligned optional range: %v", optional))
	}

	// The first Translation must include required.Start.
	if len(ts) != 0 && !ts[0].Source.Contains(required.Start) {
		return fmt.Errorf("first Translation %+v does not cover start of required range %v", ts[0], required)
	}
	for i, t := range ts {
		if !t.Source.WellFormed() || t.Source.Length() == 0 {
			return fmt.Errorf("Translation %+v has invalid Source", t)
		}
		if !hostarch.Addr(t.Source.Start).IsPageAligned() || !hostarch.Addr(t.Source.End).IsPageAligned() {
			return fmt.Errorf("Translation %+v has unaligned Source", t)
		}
		if t.File == nil {
			return fmt.Errorf("Translation %+v has nil File", t)
		}
		if !hostarch.Addr(t.Offset).IsPageAligned() {
			return fmt.Errorf("Translation %+v has unaligned Offset", t)
		}
		// Translations must be contiguous and in increasing order of
		// Translation.Source.
		if i > 0 && ts[i-1].Source.End != t.Source.Start {
			return fmt.Errorf("Translation %+v and Translation %+v are not contiguous", ts[i-1], t)
		}
		// At least part of each Translation must be required.
		if t.Source.Intersect(required).Length() == 0 {
			return fmt.Errorf("Translation %+v lies entirely outside required range %v", t, required)
		}
		// Translations must be constrained to the optional range.
		if !optional.IsSupersetOf(t.Source) {
			return fmt.Errorf("Translation %+v lies outside optional range %v", t, optional)
		}
		// Each Translation must permit a superset of requested accesses.
		if !t.Perms.SupersetOf(at) {
			return fmt.Errorf("Translation %+v does not permit all requested access types %v", t, at)
		}
	}
	// If the set of Translations does not cover the entire required range,
	// Translate must return a non-nil error explaining why.
	if terr == nil {
		if len(ts) == 0 {
			return fmt.Errorf("no Translations and no error")
		}
		if t := ts[len(ts)-1]; !t.Source.Contains(required.End - 1) {
			return fmt.Errorf("last Translation %+v does not reach end of required range %v, but Translate returned no error", t, required)
		}
	}
	return nil
}

// BusError may be returned by implementations of Mappable.Translate for errors
// that should result in SIGBUS delivery if they cause application page fault
// handling to fail.
type BusError struct {
	// Err is the original error.
	Err error
}

// Error implements error.Error.
func (b *BusError) Error() string {
	return fmt.Sprintf("BusError: %v", b.Err.Error())
}

// MappableRange represents a range of uint64 offsets into a Mappable.
//
// type MappableRange <generated using go_generics>

// String implements fmt.Stringer.String.
func (mr MappableRange) String() string {
	return fmt.Sprintf("[%#x, %#x)", mr.Start, mr.End)
}

// MappingSpace represents a mutable mapping from hostarch.Addrs to (Mappable,
// uint64 offset) pairs.
type MappingSpace interface {
	// Invalidate is called to notify the MappingSpace that values returned by
	// previous calls to Mappable.Translate for offsets mapped by addresses in
	// ar are no longer valid.
	//
	// Invalidate must not take any locks preceding mm.MemoryManager.activeMu
	// in the lock order.
	//
	// Preconditions:
	// * ar.Length() != 0.
	// * ar must be page-aligned.
	Invalidate(ar hostarch.AddrRange, opts InvalidateOpts)
}

// InvalidateOpts holds options to MappingSpace.Invalidate.
type InvalidateOpts struct {
	// InvalidatePrivate is true if private pages in the invalidated region
	// should also be discarded, causing their data to be lost.
	InvalidatePrivate bool
}

// MappingIdentity controls the lifetime of a Mappable, and provides
// information about the Mappable for /proc/[pid]/maps. It is distinct from
// Mappable because all Mappables that are coherent must compare equal to
// support the implementation of shared futexes, but different
// MappingIdentities may represent the same Mappable, in the same way that
// multiple fs.Files may represent the same fs.Inode. (This similarity is not
// coincidental; fs.File implements MappingIdentity, and some
// fs.InodeOperations implement Mappable.)
type MappingIdentity interface {
	// IncRef increments the MappingIdentity's reference count.
	IncRef()

	// DecRef decrements the MappingIdentity's reference count.
	DecRef(ctx context.Context)

	// MappedName returns the application-visible name shown in
	// /proc/[pid]/maps.
	MappedName(ctx context.Context) string

	// DeviceID returns the device number shown in /proc/[pid]/maps.
	DeviceID() uint64

	// InodeID returns the inode number shown in /proc/[pid]/maps.
	InodeID() uint64

	// Msync has the same semantics as fs.FileOperations.Fsync(ctx,
	// int64(mr.Start), int64(mr.End-1), fs.SyncData).
	// (fs.FileOperations.Fsync() takes an inclusive end, but mr.End is
	// exclusive, hence mr.End-1.) It is defined rather than Fsync so that
	// implementors don't need to depend on the fs package for fs.SyncType.
	Msync(ctx context.Context, mr MappableRange) error
}

// MLockMode specifies the memory locking behavior of a memory mapping.
type MLockMode int

// Note that the ordering of MLockModes is significant; see
// mm.MemoryManager.defMLockMode.
const (
	// MLockNone specifies that a mapping has no memory locking behavior.
	//
	// This must be the zero value for MLockMode.
	MLockNone MLockMode = iota

	// MLockEager specifies that a mapping is memory-locked, as by mlock() or
	// similar. Pages in the mapping should be made, and kept, resident in
	// physical memory as soon as possible.
	//
	// As of this writing, MLockEager does not cause memory-locking to be
	// requested from the host; it only affects the sentry's memory management
	// behavior.
	//
	// MLockEager is analogous to Linux's VM_LOCKED.
	MLockEager

	// MLockLazy specifies that a mapping is memory-locked, as by mlock() or
	// similar. Pages in the mapping should be kept resident in physical memory
	// once they have been made resident due to e.g. a page fault.
	//
	// As of this writing, MLockLazy does not cause memory-locking to be
	// requested from the host; in fact, it has virtually no effect, except for
	// interactions between mlocked pages and other syscalls.
	//
	// MLockLazy is analogous to Linux's VM_LOCKED | VM_LOCKONFAULT.
	MLockLazy
)

// MMapOpts specifies a request to create a memory mapping.
type MMapOpts struct {
	// Length is the length of the mapping.
	Length uint64

	// MappingIdentity controls the lifetime of Mappable, and provides
	// properties of the mapping shown in /proc/[pid]/maps. If MMapOpts is used
	// to successfully create a memory mapping, a reference is taken on
	// MappingIdentity.
	MappingIdentity MappingIdentity

	// Mappable is the Mappable to be mapped. If Mappable is nil, the mapping
	// is anonymous. If Mappable is not nil, it must remain valid as long as a
	// reference is held on MappingIdentity.
	Mappable Mappable

	// Offset is the offset into Mappable to map. If Mappable is nil, Offset is
	// ignored.
	Offset uint64

	// Addr is the suggested address for the mapping.
	Addr hostarch.Addr

	// Fixed specifies whether this is a fixed mapping (it must be located at
	// Addr).
	Fixed bool

	// Unmap specifies whether existing mappings in the range being mapped may
	// be replaced. If Unmap is true, Fixed must be true.
	Unmap bool

	// If Map32Bit is true, all addresses in the created mapping must fit in a
	// 32-bit integer. (Note that the "end address" of the mapping, i.e. the
	// address of the first byte *after* the mapping, need not fit in a 32-bit
	// integer.) Map32Bit is ignored if Fixed is true.
	Map32Bit bool

	// Perms is the set of permissions to the applied to this mapping.
	Perms hostarch.AccessType

	// MaxPerms limits the set of permissions that may ever apply to this
	// mapping. If Mappable is not nil, all memmap.Translations returned by
	// Mappable.Translate must support all accesses in MaxPerms.
	//
	// Preconditions: MaxAccessType should be an effective AccessType, as
	// access cannot be limited beyond effective AccessTypes.
	MaxPerms hostarch.AccessType

	// Private is true if writes to the mapping should be propagated to a copy
	// that is exclusive to the MemoryManager.
	Private bool

	// GrowsDown is true if the mapping should be automatically expanded
	// downward on guard page faults.
	GrowsDown bool

	// Precommit is true if the platform should eagerly commit resources to the
	// mapping (see platform.AddressSpace.MapFile).
	Precommit bool

	// MLockMode specifies the memory locking behavior of the mapping.
	MLockMode MLockMode

	// Hint is the name used for the mapping in /proc/[pid]/maps. If Hint is
	// empty, MappingIdentity.MappedName() will be used instead.
	//
	// TODO(jamieliu): Replace entirely with MappingIdentity?
	Hint string

	// Force means to skip validation checks of Addr and Length. It can be
	// used to create special mappings below mm.layout.MinAddr and
	// mm.layout.MaxAddr. It has to be used with caution.
	//
	// If Force is true, Unmap and Fixed must be true.
	Force bool
}

// File represents a host file that may be mapped into an platform.AddressSpace.
type File interface {
	// All pages in a File are reference-counted.

	// IncRef increments the reference count on all pages in fr.
	//
	// Preconditions:
	// * fr.Start and fr.End must be page-aligned.
	// * fr.Length() > 0.
	// * At least one reference must be held on all pages in fr. (The File
	//   interface does not provide a way to acquire an initial reference;
	//   implementors may define mechanisms for doing so.)
	IncRef(fr FileRange)

	// DecRef decrements the reference count on all pages in fr.
	//
	// Preconditions:
	// * fr.Start and fr.End must be page-aligned.
	// * fr.Length() > 0.
	// * At least one reference must be held on all pages in fr.
	DecRef(fr FileRange)

	// MapInternal returns a mapping of the given file offsets in the invoking
	// process' address space for reading and writing.
	//
	// Note that fr.Start and fr.End need not be page-aligned.
	//
	// Preconditions:
	// * fr.Length() > 0.
	// * At least one reference must be held on all pages in fr.
	//
	// Postconditions: The returned mapping is valid as long as at least one
	// reference is held on the mapped pages.
	MapInternal(fr FileRange, at hostarch.AccessType) (safemem.BlockSeq, error)

	// FD returns the file descriptor represented by the File.
	//
	// The only permitted operation on the returned file descriptor is to map
	// pages from it consistent with the requirements of AddressSpace.MapFile.
	FD() int
}

// FileRange represents a range of uint64 offsets into a File.
//
// type FileRange <generated using go_generics>

// String implements fmt.Stringer.String.
func (fr FileRange) String() string {
	return fmt.Sprintf("[%#x, %#x)", fr.Start, fr.End)
}
