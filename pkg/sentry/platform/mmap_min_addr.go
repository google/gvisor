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

package platform

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sync"
)

// systemMMapMinAddrSource is the source file.
const systemMMapMinAddrSource = "/proc/sys/vm/mmap_min_addr"

// SystemMMapMinAddr returns the minimum system address.
func SystemMMapMinAddr() hostarch.Addr {
	return hostarch.Addr(systemMMapMinAddr())
}

// MMapMinAddr is a size zero struct that implements MinUserAddress based on
// the system minimum address. It is suitable for embedding in platforms that
// rely on the system mmap, and thus require the system minimum.
type MMapMinAddr struct {
}

// MinUserAddress implements platform.MinUserAddresss.
func (*MMapMinAddr) MinUserAddress() hostarch.Addr {
	return SystemMMapMinAddr()
}

// probeMaxAddr bounds the empirical search for the minimum mappable address.
// No known configuration protects more than a small fraction of this.
const probeMaxAddr = 1 << 30 // 1 GiB

// mmapProbe returns whether the host kernel permits a fixed anonymous mapping
// at addr. It never replaces or disturbs existing mappings.
func mmapProbe(addr uintptr) (bool, error) {
	length := uintptr(hostarch.PageSize)
	ret, _, errno := unix.RawSyscall6(unix.SYS_MMAP, addr, length,
		uintptr(unix.PROT_NONE),
		uintptr(unix.MAP_PRIVATE|unix.MAP_ANONYMOUS|unix.MAP_FIXED_NOREPLACE),
		^uintptr(0) /* fd */, 0 /* offset */)
	switch errno {
	case 0:
		unix.RawSyscall(unix.SYS_MUNMAP, ret, length, 0)
		if ret != addr {
			// The kernel treated addr as a hint, i.e. it predates
			// MAP_FIXED_NOREPLACE (Linux 4.17); gVisor requires Linux 5.6+.
			return false, fmt.Errorf("mmap(%#x) probe was remapped to %#x: MAP_FIXED_NOREPLACE unsupported", addr, ret)
		}
		return true, nil
	case unix.EEXIST:
		// Something is already mapped at addr. The kernel checks
		// security_mmap_addr() before checking for overlap, so this still
		// implies that addr is at or above the enforced minimum.
		return true, nil
	case unix.EPERM:
		// addr is below the enforced minimum mappable address.
		return false, nil
	default:
		return false, fmt.Errorf("mmap(%#x) probe failed: %v", addr, errno)
	}
}

// probeMMapMinAddr empirically determines the minimum mappable address by
// binary-searching the boundary at which fixed mappings stop failing with
// EPERM.
func probeMMapMinAddr() (uint64, error) {
	pageSize := uint64(hostarch.PageSize)
	// Find the lowest mappable power-of-two multiple of the page size,
	// starting with address 0 itself.
	ok, err := mmapProbe(0)
	if err != nil {
		return 0, err
	}
	if ok {
		return 0, nil
	}
	hi := uint64(0)
	for addr := pageSize; addr <= probeMaxAddr; addr *= 2 {
		ok, err := mmapProbe(uintptr(addr))
		if err != nil {
			return 0, err
		}
		if ok {
			hi = addr
			break
		}
	}
	if hi == 0 {
		return 0, fmt.Errorf("no mappable address found at or below %#x", uint64(probeMaxAddr))
	}
	// Invariant: hi/pageSize pages is mappable, hi/(2*pageSize) pages (the
	// previous probe, or address 0 for hi == pageSize) is not. Binary-search
	// the smallest mappable page.
	hiPage := hi / pageSize
	loPage := hiPage / 2
	for hiPage-loPage > 1 {
		midPage := loPage + (hiPage-loPage)/2
		ok, err := mmapProbe(uintptr(midPage * pageSize))
		if err != nil {
			return 0, err
		}
		if ok {
			hiPage = midPage
		} else {
			loPage = midPage
		}
	}
	return hiPage * pageSize, nil
}

// systemMMapMinAddr lazily determines the system's minimum map address on
// first use, so that probing never adds to sentry initialization time.
var systemMMapMinAddr = sync.OnceValue(func() uint64 {
	b, err := os.ReadFile(systemMMapMinAddrSource)
	if err != nil {
		// In some environments the file is unreadable: for example, Android's
		// SELinux policy denies app domains read access to it. Fall back to
		// measuring the limit empirically.
		probed, probeErr := probeMMapMinAddr()
		if probeErr != nil {
			panic(fmt.Sprintf("couldn't read %s (%v), and probing the minimum mappable address failed: %v", systemMMapMinAddrSource, err, probeErr))
		}
		log.Infof("Couldn't read %s (%v); using empirically probed minimum mappable address %#x.", systemMMapMinAddrSource, err, probed)
		return probed
	}

	// Parse the result.
	val, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		panic(fmt.Sprintf("couldn't parse %s from %s: %v", string(b), systemMMapMinAddrSource, err))
	}
	return val
})
