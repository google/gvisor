// Copyright 2020 The gVisor Authors.
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

package host

import (
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/usermem"
)

// inodePlatformFile implements platform.File. It exists solely because inode
// cannot implement both kernfs.Inode.IncRef and platform.File.IncRef.
//
// inodePlatformFile should only be used if inode.canMap is true.
type inodePlatformFile struct {
	*inode

	// fdRefsMu protects fdRefs.
	fdRefsMu sync.Mutex

	// fdRefs counts references on platform.File offsets. It is used solely for
	// memory accounting.
	fdRefs fsutil.FrameRefSet

	// fileMapper caches mappings of the host file represented by this inode.
	fileMapper fsutil.HostFileMapper

	// fileMapperInitOnce is used to lazily initialize fileMapper.
	fileMapperInitOnce sync.Once
}

// IncRef implements platform.File.IncRef.
//
// Precondition: i.inode.canMap must be true.
func (i *inodePlatformFile) IncRef(fr platform.FileRange) {
	i.fdRefsMu.Lock()
	i.fdRefs.IncRefAndAccount(fr)
	i.fdRefsMu.Unlock()
}

// DecRef implements platform.File.DecRef.
//
// Precondition: i.inode.canMap must be true.
func (i *inodePlatformFile) DecRef(fr platform.FileRange) {
	i.fdRefsMu.Lock()
	i.fdRefs.DecRefAndAccount(fr)
	i.fdRefsMu.Unlock()
}

// MapInternal implements platform.File.MapInternal.
//
// Precondition: i.inode.canMap must be true.
func (i *inodePlatformFile) MapInternal(fr platform.FileRange, at usermem.AccessType) (safemem.BlockSeq, error) {
	return i.fileMapper.MapInternal(fr, i.hostFD, at.Write)
}

// FD implements platform.File.FD.
func (i *inodePlatformFile) FD() int {
	return i.hostFD
}

// AddMapping implements memmap.Mappable.AddMapping.
//
// Precondition: i.inode.canMap must be true.
func (i *inode) AddMapping(ctx context.Context, ms memmap.MappingSpace, ar usermem.AddrRange, offset uint64, writable bool) error {
	i.mapsMu.Lock()
	mapped := i.mappings.AddMapping(ms, ar, offset, writable)
	for _, r := range mapped {
		i.pf.fileMapper.IncRefOn(r)
	}
	i.mapsMu.Unlock()
	return nil
}

// RemoveMapping implements memmap.Mappable.RemoveMapping.
//
// Precondition: i.inode.canMap must be true.
func (i *inode) RemoveMapping(ctx context.Context, ms memmap.MappingSpace, ar usermem.AddrRange, offset uint64, writable bool) {
	i.mapsMu.Lock()
	unmapped := i.mappings.RemoveMapping(ms, ar, offset, writable)
	for _, r := range unmapped {
		i.pf.fileMapper.DecRefOn(r)
	}
	i.mapsMu.Unlock()
}

// CopyMapping implements memmap.Mappable.CopyMapping.
//
// Precondition: i.inode.canMap must be true.
func (i *inode) CopyMapping(ctx context.Context, ms memmap.MappingSpace, srcAR, dstAR usermem.AddrRange, offset uint64, writable bool) error {
	return i.AddMapping(ctx, ms, dstAR, offset, writable)
}

// Translate implements memmap.Mappable.Translate.
//
// Precondition: i.inode.canMap must be true.
func (i *inode) Translate(ctx context.Context, required, optional memmap.MappableRange, at usermem.AccessType) ([]memmap.Translation, error) {
	mr := optional
	return []memmap.Translation{
		{
			Source: mr,
			File:   &i.pf,
			Offset: mr.Start,
			Perms:  usermem.AnyAccess,
		},
	}, nil
}

// InvalidateUnsavable implements memmap.Mappable.InvalidateUnsavable.
//
// Precondition: i.inode.canMap must be true.
func (i *inode) InvalidateUnsavable(ctx context.Context) error {
	// We expect the same host fd across save/restore, so all translations
	// should be valid.
	return nil
}
