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

package controlapi

import (
	"fmt"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/pkg/urpc"
)

// MemoryUsageOpts contains usage options.
type MemoryUsageOpts struct {
	// Full indicates that a full accounting should be done. If Full is not
	// specified, then a partial accounting will be done, and Unknown will
	// contain a majority of memory. See Collect for more information.
	Full bool `json:"Full"`
}

// MemoryUsage is a memory usage structure.
type MemoryUsage struct {
	Unknown   uint64 `json:"Unknown"`
	System    uint64 `json:"System"`
	Anonymous uint64 `json:"Anonymous"`
	PageCache uint64 `json:"PageCache"`
	Mapped    uint64 `json:"Mapped"`
	Tmpfs     uint64 `json:"Tmpfs"`
	Ramdiskfs uint64 `json:"Ramdiskfs"`
	Total     uint64 `json:"Total"`
}

// MemoryUsageFileOpts contains usage file options.
type MemoryUsageFileOpts struct {
	// Version is used to ensure both sides agree on the format of the
	// shared memory buffer.
	Version uint64 `json:"Version"`
}

// MemoryUsageFile contains the file handle to the usage file.
type MemoryUsageFile struct {
	urpc.FilePayload
}

// MemoryUsageRecord contains the mapping and platform memory file.
type MemoryUsageRecord struct {
	mmap  uintptr
	stats *usage.RTMemoryStats
	mf    os.File
}

// NewMemoryUsageRecord creates a new MemoryUsageRecord from usageFile and
// platformFile.
func NewMemoryUsageRecord(usageFile, platformFile os.File) (*MemoryUsageRecord, error) {
	mmap, _, e := unix.RawSyscall6(unix.SYS_MMAP, 0, usage.RTMemoryStatsSize, unix.PROT_READ, unix.MAP_SHARED, usageFile.Fd(), 0)
	if e != 0 {
		return nil, fmt.Errorf("mmap returned %d, want 0", e)
	}

	m := MemoryUsageRecord{
		mmap:  mmap,
		stats: usage.RTMemoryStatsPointer(mmap),
		mf:    platformFile,
	}

	runtime.SetFinalizer(&m, finalizer)
	return &m, nil
}

func finalizer(m *MemoryUsageRecord) {
	unix.RawSyscall(unix.SYS_MUNMAP, m.mmap, usage.RTMemoryStatsSize, 0)
}

// Fetch fetches the usage info from a MemoryUsageRecord.
func (m *MemoryUsageRecord) Fetch() (mapped, unknown, total uint64, err error) {
	var stat unix.Stat_t
	if err := unix.Fstat(int(m.mf.Fd()), &stat); err != nil {
		return 0, 0, 0, err
	}
	fmem := uint64(stat.Blocks) * 512
	rtmapped := m.stats.RTMapped.Load()
	return rtmapped, fmem, rtmapped + fmem, nil
}
