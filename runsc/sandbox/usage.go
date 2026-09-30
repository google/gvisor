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

package sandbox

import (
	"fmt"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/sentry/usage"
)

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
