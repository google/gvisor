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

package mm

import (
	"gvisor.googlesource.com/gvisor/pkg/refs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/memmap"
	"gvisor.googlesource.com/gvisor/pkg/sentry/platform"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usage"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

// SpecialMappable implements memmap.MappingIdentity and memmap.Mappable with
// semantics similar to Linux's mm/mmap.c:_install_special_mapping(), except
// that SpecialMappable takes ownership of the memory that it represents
// (_install_special_mapping() does not.)
//
// +stateify savable
type SpecialMappable struct {
	refs.AtomicRefCount

	p    platform.Platform
	fr   platform.FileRange
	name string
}

// NewSpecialMappable returns a SpecialMappable that owns fr, which represents
// offsets in p.Memory() that contain the SpecialMappable's data. The
// SpecialMappable will use the given name in /proc/[pid]/maps.
//
// Preconditions: fr.Length() != 0.
func NewSpecialMappable(name string, p platform.Platform, fr platform.FileRange) *SpecialMappable {
	return &SpecialMappable{p: p, fr: fr, name: name}
}

// DecRef implements refs.RefCounter.DecRef.
func (m *SpecialMappable) DecRef() {
	m.AtomicRefCount.DecRefWithDestructor(func() {
		m.p.Memory().DecRef(m.fr)
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
func (m *SpecialMappable) AddMapping(ctx context.Context, ms memmap.MappingSpace, ar usermem.AddrRange, offset uint64) error {
	return nil
}

// RemoveMapping implements memmap.Mappable.RemoveMapping.
func (m *SpecialMappable) RemoveMapping(ctx context.Context, ms memmap.MappingSpace, ar usermem.AddrRange, offset uint64) {
}

// CopyMapping implements memmap.Mappable.CopyMapping.
func (m *SpecialMappable) CopyMapping(ctx context.Context, ms memmap.MappingSpace, srcAR, dstAR usermem.AddrRange, offset uint64) error {
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
				File:   m.p.Memory(),
				Offset: m.fr.Start + source.Start,
			},
		}, err
	}
	return nil, err
}

// InvalidateUnsavable implements memmap.Mappable.InvalidateUnsavable.
func (m *SpecialMappable) InvalidateUnsavable(ctx context.Context) error {
	// Since data is stored in platform.Platform.Memory(), the contents of
	// which are preserved across save/restore, we don't need to do anything.
	return nil
}

// Platform returns the Platform whose Memory stores the SpecialMappable's
// contents.
func (m *SpecialMappable) Platform() platform.Platform {
	return m.p
}

// FileRange returns the offsets into Platform().Memory() that store the
// SpecialMappable's contents.
func (m *SpecialMappable) FileRange() platform.FileRange {
	return m.fr
}

// Length returns the length of the SpecialMappable.
func (m *SpecialMappable) Length() uint64 {
	return m.fr.Length()
}

// NewSharedAnonMappable returns a SpecialMappable that implements the
// semantics of mmap(MAP_SHARED|MAP_ANONYMOUS) and mappings of /dev/zero.
//
// TODO: The use of SpecialMappable is a lazy code reuse hack. Linux
// uses an ephemeral file created by mm/shmem.c:shmem_zero_setup(); we should
// do the same to get non-zero device and inode IDs.
func NewSharedAnonMappable(length uint64, p platform.Platform) (*SpecialMappable, error) {
	if length == 0 || length != uint64(usermem.Addr(length).RoundDown()) {
		return nil, syserror.EINVAL
	}
	fr, err := p.Memory().Allocate(length, usage.Anonymous)
	if err != nil {
		return nil, err
	}
	return NewSpecialMappable("/dev/zero (deleted)", p, fr), nil
}
