// Copyright 2026 The gVisor Authors.
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

package fsutil

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
)

// MmapNoInternalFile implements MmapFile by causing calls to MapInternal to fail.
// The File may still be mapped into platform.AddressSpaces, i.e. application
// address spaces, except on platform/kvm.
//
// MmapFileRefs.Closer must be set to MmapNoInternalFile.Close before calling
// MmapNoInternalFile.MappableRelease.
//
// MmapNoInternalFile is used for device files that are not mappable into the sentry
// for esoteric reasons (which should be documented for each such file), and
// for device files for which sentry mapping has not been tested (but might
// work with MmapPreciseFile, or a custom implementation of memmap.File).
//
// +stateify savable
type MmapNoInternalFile struct {
	memmap.NoMapInternal
	MmapFileRefs

	fd int // immutable after SetFD
}

// SetFD implements MmapFile.SetFD.
func (f *MmapNoInternalFile) SetFD(fd int) {
	f.fd = fd
}

// Close implements io.Closer.Close for f.MmapFileRefs.Closer.
func (f *MmapNoInternalFile) Close() error {
	var err error
	if f.fd >= 0 {
		err = unix.Close(f.fd)
		f.fd = -1
	}
	return err
}

// DataFD implements memmap.File.DataFD.
func (f *MmapNoInternalFile) DataFD(fr memmap.FileRange) (int, error) {
	return f.fd, nil
}

// FD implements memmap.File.FD.
func (f *MmapNoInternalFile) FD() int {
	return f.fd
}
