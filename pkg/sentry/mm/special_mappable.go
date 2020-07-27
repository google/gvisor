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

package mm

import (
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
)

// SpecialMappable implements memmap.MappingIdentity and memmap.Mappable with
// semantics similar to Linux's mm/mmap.c:_install_special_mapping(), except
// that SpecialMappable takes ownership of the memory that it represents
// (_install_special_mapping() does not.)
//
// +stateify savable
type SpecialMappable struct {
	refs.AtomicRefCount

	mfp  pgalloc.MemoryFileProvider
	fr   memmap.FileRange
	name string
}

// NewSpecialMappable returns a SpecialMappable that owns fr, which represents
// offsets in mfp.MemoryFile() that contain the SpecialMappable's data. The
// SpecialMappable will use the given name in /proc/[pid]/maps.
//
// Preconditions: fr.Length() != 0.
func NewSpecialMappable(name string, mfp pgalloc.MemoryFileProvider, fr memmap.FileRange) *SpecialMappable {
	m := SpecialMappable{mfp: mfp, fr: fr, name: name}
	m.EnableLeakCheck("mm.SpecialMappable")
	return &m
}

// DecRef implements refs.RefCounter.DecRef.
func (m *SpecialMappable) DecRef() {
	m.AtomicRefCount.DecRefWithDestructor(func() {
		m.mfp.MemoryFile().DecRef(m.fr)
	})
}

// MappedName implements memmap.MappingIdentity.MappedName.
func (m *SpecialMappable) MappedName(ctx context.Context) string {
	return m.name
}

// DeviceID implements memmap.MappingIdentity.DeviceID.
func (m *SpecialMappable) DeviceID() uint64 {
	return 0
}

// InodeID implements memmap.MappingIdentity.InodeID.
func (m *SpecialMappable) InodeID() uint64 {
	return 0
}

// Msync implements memmap.MappingIdentity.Msync.
func (m *SpecialMappable) Msync(ctx context.Context, mr memmap.MappableRange) error {
	// Linux: vm_file is NULL, causing msync to skip it entirely.
	return nil
}

// AddMapping implements memmap.Mappable.AddMapping.
func (*SpecialMappable) AddMapping(context.Context, memmap.MappingSpace, usermem.AddrRange, uint64, bool) error {
	return nil
}

// RemoveMapping implements memmap.Mappable.RemoveMapping.
func (*SpecialMappable) RemoveMapping(context.Context, memmap.MappingSpace, usermem.AddrRange, uint64, bool) {
}

// CopyMapping implements memmap.Mappable.CopyMapping.
func (*SpecialMappable) CopyMapping(context.Context, memmap.MappingSpace, usermem.AddrRange, usermem.AddrRange, uint64, bool) error {
	return nil
}

// Translate implements memmap.Mappable.Translate.
func (m *SpecialMappable) Translate(ctx context.Context, required, optional memmap.MappableRange, at usermem.AccessType) ([]memmap.Translation, error) {
	var err error
	if required.End > m.fr.Length() {
		err = &memmap.BusError{syserror.EFAULT}
	}
	if source := optional.Intersect(memmap.MappableRange{0, m.fr.Length()}); source.Length() != 0 {
		return []memmap.Translation{
			{
				Source: source,
				File:   m.mfp.MemoryFile(),
				Offset: m.fr.Start + source.Start,
				Perms:  usermem.AnyAccess,
			},
		}, err
	}
	return nil, err
}

// InvalidateUnsavable implements memmap.Mappable.InvalidateUnsavable.
func (m *SpecialMappable) InvalidateUnsavable(ctx context.Context) error {
	// Since data is stored in pgalloc.MemoryFile, the contents of which are
	// preserved across save/restore, we don't need to do anything.
	return nil
}

// MemoryFileProvider returns the MemoryFileProvider whose MemoryFile stores
// the SpecialMappable's contents.
func (m *SpecialMappable) MemoryFileProvider() pgalloc.MemoryFileProvider {
	return m.mfp
}

// FileRange returns the offsets into MemoryFileProvider().MemoryFile() that
// store the SpecialMappable's contents.
func (m *SpecialMappable) FileRange() memmap.FileRange {
	return m.fr
}

// Length returns the length of the SpecialMappable.
func (m *SpecialMappable) Length() uint64 {
	return m.fr.Length()
}

// NewSharedAnonMappable returns a SpecialMappable that implements the
// semantics of mmap(MAP_SHARED|MAP_ANONYMOUS) and mappings of /dev/zero.
//
// TODO(jamieliu): The use of SpecialMappable is a lazy code reuse hack. Linux
// uses an ephemeral file created by mm/shmem.c:shmem_zero_setup(); we should
// do the same to get non-zero device and inode IDs.
func NewSharedAnonMappable(length uint64, mfp pgalloc.MemoryFileProvider) (*SpecialMappable, error) {
	if length == 0 {
		return nil, syserror.EINVAL
	}
	alignedLen, ok := usermem.Addr(length).RoundUp()
	if !ok {
		return nil, syserror.EINVAL
	}
	fr, err := mfp.MemoryFile().Allocate(uint64(alignedLen), usage.Anonymous)
	if err != nil {
		return nil, err
	}
	return NewSpecialMappable("/dev/zero (deleted)", mfp, fr), nil
}
