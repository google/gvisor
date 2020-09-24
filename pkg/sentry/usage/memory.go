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
	"sync/atomic"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/bits"
	"gvisor.dev/gvisor/pkg/memutil"
	"gvisor.dev/gvisor/pkg/sync"
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
	// abitrarily populate/decommit the pages, which it may do for various
	// reasons (ex. host memory reclaim, NUMA balancing).
	//
	// This memory kind is backed by the host pagecache, via host mmaps.
	Mapped
)

// MemoryStats tracks application memory usage in bytes. All fields correspond to the
// memory category with the same name. This object is thread-safe if accessed
// through the provided methods. The public fields may be safely accessed
// directly on a copy of the object obtained from Memory.Copy().
type MemoryStats struct {
	// +checkatomic
	System uint64
	// +checkatomic
	Anonymous uint64
	// +checkatomic
	PageCache uint64
	// +checkatomic
	Tmpfs uint64
	// +checkatomic
	Mapped uint64
	// +checkatomic
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
	// +checkatomic
	RTMapped uint64
}

// MemoryLocked is Memory with access methods.
type MemoryLocked struct {
	mu sync.RWMutex
	// MemoryStats records the memory stats.
	MemoryStats
	// RTMemoryStats records the memory stats that need to be exposed through
	// shared page.
	*RTMemoryStats
	// File is the backing file storing the memory stats.
	File *os.File
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
	mmap, err := unix.Mmap(int(file.Fd()), 0, int(RTMemoryStatsSize), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return fmt.Errorf("error mapping usage file: %v", err)
	}

	MemoryAccounting = &MemoryLocked{
		File:          file,
		RTMemoryStats: RTMemoryStatsPointer(mmap),
	}
	return nil
}

// MemoryAccounting is the global memory stats.
//
// There is no need to save or restore the global memory accounting object,
// because individual frame kinds are saved and charged only when they become
// resident.
var MemoryAccounting *MemoryLocked

func (m *MemoryLocked) incLocked(val uint64, kind MemoryKind) {
	switch kind {
	case System:
		atomic.AddUint64(&m.System, val)
	case Anonymous:
		atomic.AddUint64(&m.Anonymous, val)
	case PageCache:
		atomic.AddUint64(&m.PageCache, val)
	case Mapped:
		atomic.AddUint64(&m.RTMapped, val)
	case Tmpfs:
		atomic.AddUint64(&m.Tmpfs, val)
	case Ramdiskfs:
		atomic.AddUint64(&m.Ramdiskfs, val)
	default:
		panic(fmt.Sprintf("invalid memory kind: %v", kind))
	}
}

// Inc adds an additional usage of 'val' bytes to memory category 'kind'.
//
// This method is thread-safe.
func (m *MemoryLocked) Inc(val uint64, kind MemoryKind) {
	m.mu.RLock()
	m.incLocked(val, kind)
	m.mu.RUnlock()
}

func (m *MemoryLocked) decLocked(val uint64, kind MemoryKind) {
	switch kind {
	case System:
		atomic.AddUint64(&m.System, ^(val - 1))
	case Anonymous:
		atomic.AddUint64(&m.Anonymous, ^(val - 1))
	case PageCache:
		atomic.AddUint64(&m.PageCache, ^(val - 1))
	case Mapped:
		atomic.AddUint64(&m.RTMapped, ^(val - 1))
	case Tmpfs:
		atomic.AddUint64(&m.Tmpfs, ^(val - 1))
	case Ramdiskfs:
		atomic.AddUint64(&m.Ramdiskfs, ^(val - 1))
	default:
		panic(fmt.Sprintf("invalid memory kind: %v", kind))
	}
}

// Dec remove a usage of 'val' bytes from memory category 'kind'.
//
// This method is thread-safe.
func (m *MemoryLocked) Dec(val uint64, kind MemoryKind) {
	m.mu.RLock()
	m.decLocked(val, kind)
	m.mu.RUnlock()
}

// Move moves a usage of 'val' bytes from 'from' to 'to'.
//
// This method is thread-safe.
func (m *MemoryLocked) Move(val uint64, to MemoryKind, from MemoryKind) {
	m.mu.RLock()
	// Just call decLocked and incLocked directly. We held the RLock to
	// protect against concurrent callers to Total().
	m.decLocked(val, from)
	m.incLocked(val, to)
	m.mu.RUnlock()
}

// totalLocked returns a total usage.
//
// Precondition: must be called when locked.
func (m *MemoryLocked) totalLocked() (total uint64) {
	total += atomic.LoadUint64(&m.System)
	total += atomic.LoadUint64(&m.Anonymous)
	total += atomic.LoadUint64(&m.PageCache)
	total += atomic.LoadUint64(&m.RTMapped)
	total += atomic.LoadUint64(&m.Tmpfs)
	total += atomic.LoadUint64(&m.Ramdiskfs)
	return
}

// Total returns a total memory usage.
//
// This method is thread-safe.
func (m *MemoryLocked) Total() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.totalLocked()
}

// Copy returns a copy of the structure with a total.
//
// This method is thread-safe.
func (m *MemoryLocked) Copy() (MemoryStats, uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ms := m.MemoryStats
	ms.Mapped = m.RTMapped // checkatomic: safe.
	return ms, m.totalLocked()
}

// These options control how much total memory the is reported to the application.
// They may only be set before the application starts executing, and must not
// be modified.
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
