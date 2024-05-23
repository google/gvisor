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

package usage

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/bits"
	"gvisor.dev/gvisor/pkg/memutil"
)

// MemoryKind represents a type of memory used by the application.
//
// For efficiency reasons, it is assumed that the Memory implementation is
// responsible for specific stats (documented below), and those may be reported
// in aggregate independently. See the platform.Memory interface as well as the
// control.Usage.Collect method for more information.
type MemoryKind int

const (
	// System represents miscellaneous system memory. This may include
	// memory that is in the process of being reclaimed, system caches,
	// page tables, swap, etc.
	//
	// This memory kind is backed by platform memory.
	System MemoryKind = iota

	// Anonymous represents anonymous application memory.
	//
	// This memory kind is backed by platform memory.
	Anonymous

	// PageCache represents memory allocated to back sandbox-visible files that
	// do not have a local fd. The contents of these files are buffered in
	// memory to support application mmaps.
	//
	// This memory kind is backed by platform memory.
	PageCache

	// Tmpfs represents memory used by the sandbox-visible tmpfs.
	//
	// This memory kind is backed by platform memory.
	Tmpfs

	// Ramdiskfs represents memory used by the ramdiskfs.
	//
	// This memory kind is backed by platform memory.
	Ramdiskfs

	// Mapped represents memory related to files which have a local fd on the
	// host, and thus can be directly mapped. Typically these are files backed
	// by gofers with donated-fd support. Note that this value may not track the
	// exact amount of memory used by mapping on the host, because we don't have
	// any visibility into the host kernel memory management. In particular,
	// once we map some part of a host file, the host kernel is free to
	// arbitrarily populate/decommit the pages, which it may do for various
	// reasons (ex. host memory reclaim, NUMA balancing).
	//
	// This memory kind is backed by the host pagecache, via host mmaps.
	Mapped
)

// memoryStats tracks application memory usage in bytes. All fields correspond to the
// memory category with the same name. This object is thread-safe if accessed
// through the provided methods. The public fields may be safely accessed
// directly on a copy of the object obtained from Memory.Copy().
type memoryStats struct {
	System    atomicbitops.Uint64
	Anonymous atomicbitops.Uint64
	PageCache atomicbitops.Uint64
	Tmpfs     atomicbitops.Uint64
	Mapped    atomicbitops.Uint64
	Ramdiskfs atomicbitops.Uint64
}

// incLocked adds a usage of 'val' bytes from memory category 'kind'.
//
// Precondition: must be called when locked.
func (ms *memoryStats) incLocked(val uint64, kind MemoryKind) {
	switch kind {
	case System:
		ms.System.Add(val)
	case Anonymous:
		ms.Anonymous.Add(val)
	case PageCache:
		ms.PageCache.Add(val)
	case Mapped:
		ms.Mapped.Add(val)
	case Tmpfs:
		ms.Tmpfs.Add(val)
	case Ramdiskfs:
		ms.Ramdiskfs.Add(val)
	default:
		panic(fmt.Sprintf("invalid memory kind: %v", kind))
	}
}

// decLocked removes a usage of 'val' bytes from memory category 'kind'.
//
// Precondition: must be called when locked.
func (ms *memoryStats) decLocked(val uint64, kind MemoryKind) {
	switch kind {
	case System:
		ms.System.Add(^(val - 1))
	case Anonymous:
		ms.Anonymous.Add(^(val - 1))
	case PageCache:
		ms.PageCache.Add(^(val - 1))
	case Mapped:
		ms.Mapped.Add(^(val - 1))
	case Tmpfs:
		ms.Tmpfs.Add(^(val - 1))
	case Ramdiskfs:
		ms.Ramdiskfs.Add(^(val - 1))
	default:
		panic(fmt.Sprintf("invalid memory kind: %v", kind))
	}
}

// totalLocked returns a total usage.
//
// Precondition: must be called when locked.
func (ms *memoryStats) totalLocked() (total uint64) {
	total += ms.System.RacyLoad()
	total += ms.Anonymous.RacyLoad()
	total += ms.PageCache.RacyLoad()
	total += ms.Mapped.RacyLoad()
	total += ms.Tmpfs.RacyLoad()
	total += ms.Ramdiskfs.RacyLoad()
	return
}

// copyLocked returns a copy of the structure.
//
// Precondition: must be called when locked.
func (ms *memoryStats) copyLocked() MemoryStats {
	return MemoryStats{
		System:    ms.System.RacyLoad(),
		Anonymous: ms.Anonymous.RacyLoad(),
		PageCache: ms.PageCache.RacyLoad(),
		Tmpfs:     ms.Tmpfs.RacyLoad(),
		Mapped:    ms.Mapped.RacyLoad(),
		Ramdiskfs: ms.Ramdiskfs.RacyLoad(),
	}
}

// MemoryStats tracks application memory usage in bytes. All fields correspond
// to the memory category with the same name.
type MemoryStats struct {
	System    uint64
	Anonymous uint64
	PageCache uint64
	Tmpfs     uint64
	Mapped    uint64
	Ramdiskfs uint64
}

// RTMemoryStats contains the memory usage values that need to be directly
// exposed through a shared memory file for real-time access. These are
// categories not backed by platform memory. For details about how this works,
// see the memory accounting docs.
//
// N.B. Please keep the struct in sync with the API. Notably, changes to this
// struct requires a version bump and addition of compatibility logic in the
// control server. As a special-case, adding fields without re-ordering existing
// ones do not require a version bump because the mapped page we use is
// initially zeroed. Any added field will be ignored by an older API and will be
// zero if read by a newer API.
type RTMemoryStats struct {
	RTMapped atomicbitops.Uint64
}

// MemoryLocked is Memory with access methods.
type MemoryLocked struct {
	mu memoryMutex
	// memoryStats records the memory stats.
	memoryStats
	// RTMemoryStats records the memory stats that need to be exposed through
	// shared page.
	*RTMemoryStats
	// File is the backing file storing the memory stats.
	File *os.File
	// MemCgIDToMemStats is the map of cgroup ids to memory stats.
	MemCgIDToMemStats map[uint32]*memoryStats
}

// Init initializes global 'MemoryAccounting'.
func Init() error {
	const name = "memory-usage"
	fd, err := memutil.CreateMemFD(name, 0)
	if err != nil {
		return fmt.Errorf("error creating usage file: %v", err)
	}
	file := os.NewFile(uintptr(fd), name)
	if err := file.Truncate(int64(RTMemoryStatsSize)); err != nil {
		return fmt.Errorf("error truncating usage file: %v", err)
	}
	// Note: We rely on the returned page being initially zeroed. This will
	// always be the case for a newly mapped page from /dev/shm. If we obtain
	// the shared memory through some other means in the future, we may have to
	// explicitly zero the page.
	mmap, err := memutil.MapFile(0, RTMemoryStatsSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED, file.Fd(), 0)
	if err != nil {
		return fmt.Errorf("error mapping usage file: %v", err)
	}

	MemoryAccounting = &MemoryLocked{
		File:              file,
		RTMemoryStats:     RTMemoryStatsPointer(mmap),
		MemCgIDToMemStats: make(map[uint32]*memoryStats),
	}
	return nil
}

// MemoryAccounting is the global memory stats.
//
// There is no need to save or restore the global memory accounting object,
// because individual frame kinds are saved and charged only when they become
// resident.
var MemoryAccounting *MemoryLocked

func (m *MemoryLocked) incLockedPerCg(val uint64, kind MemoryKind, memCgID uint32) {
	if _, ok := m.MemCgIDToMemStats[memCgID]; !ok {
		m.MemCgIDToMemStats[memCgID] = &memoryStats{}
	}

	ms := m.MemCgIDToMemStats[memCgID]
	ms.incLocked(val, kind)
}

// Inc adds an additional usage of 'val' bytes to memory category 'kind' for a
// cgroup with id 'memCgID'. If 'memCgID' is zero, the memory is accounted only
// for the total memory usage.
//
// This method is thread-safe.
func (m *MemoryLocked) Inc(val uint64, kind MemoryKind, memCgID uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.incLocked(val, kind)
	if memCgID != 0 {
		m.incLockedPerCg(val, kind, memCgID)
	}

	// If the memory category is 'Mapped', update RTMapped.
	if kind == Mapped {
		m.RTMapped.Add(val)
	}
}

func (m *MemoryLocked) decLockedPerCg(val uint64, kind MemoryKind, memCgID uint32) {
	if _, ok := m.MemCgIDToMemStats[memCgID]; !ok {
		panic(fmt.Sprintf("invalid memory cgroup id: %v", memCgID))
	}

	ms := m.MemCgIDToMemStats[memCgID]
	ms.decLocked(val, kind)
}

// Dec removes a usage of 'val' bytes from memory category 'kind' for a cgroup
// with id 'memCgID'. If 'memCgID' is zero, the memory is removed only from the
// total usage.
//
// This method is thread-safe.
func (m *MemoryLocked) Dec(val uint64, kind MemoryKind, memCgID uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.decLocked(val, kind)
	if memCgID != 0 {
		m.decLockedPerCg(val, kind, memCgID)
	}

	// If the memory category is 'Mapped', update RTMapped.
	if kind == Mapped {
		m.RTMapped.Add(^(val - 1))
	}
}

// Move moves a usage of 'val' bytes from 'from' to 'to' for a cgroup with
// id 'memCgID'.
//
// This method is thread-safe.
func (m *MemoryLocked) Move(val uint64, to MemoryKind, from MemoryKind, memCgID uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Just call decLocked and incLocked directly. We held the Lock to
	// protect against concurrent callers to Total().
	m.decLocked(val, from)
	m.incLocked(val, to)

	if memCgID != 0 {
		m.decLockedPerCg(val, from, memCgID)
		m.incLockedPerCg(val, to, memCgID)
	}
}

// Total returns a total memory usage.
//
// This method is thread-safe.
func (m *MemoryLocked) Total() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.totalLocked()
}

// TotalPerCg returns a total memory usage for a cgroup.
//
// This method is thread-safe.
func (m *MemoryLocked) TotalPerCg(memCgID uint32) uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Total memory usage including the sentry memory.
	if memCgID == 0 {
		return m.totalLocked()
	}
	// Memory usage for all cgroups except sentry memory.
	ms, ok := m.MemCgIDToMemStats[memCgID]
	if !ok {
		return 0
	}
	return ms.totalLocked()
}

// Copy returns a copy of the structure with a total.
//
// This method is thread-safe.
func (m *MemoryLocked) Copy() (MemoryStats, uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.copyLocked(), m.totalLocked()
}

// CopyPerCg returns a copy of the structure with a total for a cgroup.
//
// This method is thread-safe.
func (m *MemoryLocked) CopyPerCg(memCgID uint32) (MemoryStats, uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Total memory usage including the sentry memory.
	if memCgID == 0 {
		return m.copyLocked(), m.totalLocked()
	}
	// Memory usage for all cgroups except sentry memory.
	ms, ok := m.MemCgIDToMemStats[memCgID]
	if !ok {
		return MemoryStats{}, 0
	}
	return ms.copyLocked(), ms.totalLocked()
}

// These options control how much total memory the is reported to the
// application. They may only be set before the application starts executing,
// and must not be modified.
var (
	// MinimumTotalMemoryBytes is the minimum reported total system memory.
	MinimumTotalMemoryBytes uint64 = 2 << 30 // 2 GB

	// MaximumTotalMemoryBytes is the maximum reported total system memory.
	// The 0 value indicates no maximum.
	MaximumTotalMemoryBytes uint64
)

// TotalMemory returns the "total usable memory" available.
//
// This number doesn't really have a true value so it's based on the following
// inputs and further bounded to be above the MinumumTotalMemoryBytes and below
// MaximumTotalMemoryBytes.
//
// memSize should be the platform.Memory size reported by platform.Memory.TotalSize()
// used is the total memory reported by MemoryLocked.Total()
func TotalMemory(memSize, used uint64) uint64 {
	if memSize < MinimumTotalMemoryBytes {
		memSize = MinimumTotalMemoryBytes
	}
	if memSize < used {
		memSize = used
		// Bump memSize to the next largest power of 2, if one exists, so
		// that MemFree isn't 0.
		if msb := bits.MostSignificantOne64(memSize); msb < 63 {
			memSize = uint64(1) << (uint(msb) + 1)
		}
	}
	if MaximumTotalMemoryBytes > 0 && memSize > MaximumTotalMemoryBytes {
		memSize = MaximumTotalMemoryBytes
	}
	return memSize
}
