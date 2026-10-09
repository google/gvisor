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

package time

import (
	"fmt"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/sync"
)

// tscOffset is the guest TSC offset applied by the platform (e.g. KVM).
//
// It is process-global: all platform instances in a process must apply the
// same offset.
//
// It is kept separately from the word that modeOffset points to because that
// word reads as zero in guest mode, whereas tscOffset must read as the offset
// in both modes (see rawHostRdtsc and TSCOffset).
var tscOffset atomicbitops.Int64

// modeOffset points to the value to add to the hardware counter to obtain a
// value in the guest TSC domain, or is nil if no TSC offset is in effect.
//
// When non-nil, it points to the first word of the host page allocated by
// EnableGuestAliasedOffset. The platform maps the same virtual address to the
// guest page in its guest page tables. The word therefore reads as tscOffset
// in host mode, where the hardware counter is the raw host TSC, and as zero in
// guest mode, where the hardware already applies tscOffset. Both modes thus
// compute the same guest TSC value without having to detect the current mode.
var modeOffset atomic.Pointer[atomicbitops.Int64]

// aliasedOffset holds the pages backing modeOffset.
var aliasedOffset struct {
	once sync.Once

	// hostPage points to the page holding tscOffset. It is nil until
	// EnableGuestAliasedOffset succeeds.
	hostPage atomic.Pointer[atomicbitops.Int64]

	// guestPage is the address of a read-only page that holds zero forever.
	guestPage uintptr

	// err is the error from allocating the pages, if any.
	err error
}

// EnableGuestAliasedOffset allocates the pages that let a platform apply a TSC
// offset to guest mode, and returns their addresses.
//
// The page at guestVA always holds zero. The platform must map it read-only at
// hostVA in the page tables used by the sentry in guest mode, before calling
// SetTSCOffset with a non-zero offset. The pages are allocated once per
// process; subsequent calls return the same addresses.
func EnableGuestAliasedOffset() (hostVA, guestVA uintptr, err error) {
	aliasedOffset.once.Do(func() {
		pageSize := unix.Getpagesize()
		mem, mmapErr := unix.Mmap(-1, 0, 2*pageSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
		if mmapErr != nil {
			aliasedOffset.err = fmt.Errorf("failed to allocate TSC offset pages: %w", mmapErr)
			return
		}
		// The guest page must hold zero forever; drop write access so that
		// a stray host write cannot corrupt guest-mode TSC reads.
		if mprotectErr := unix.Mprotect(mem[pageSize:], unix.PROT_READ); mprotectErr != nil {
			unix.Munmap(mem)
			aliasedOffset.err = fmt.Errorf("failed to protect TSC offset guest page: %w", mprotectErr)
			return
		}
		aliasedOffset.guestPage = uintptr(unsafe.Pointer(&mem[pageSize]))
		aliasedOffset.hostPage.Store((*atomicbitops.Int64)(unsafe.Pointer(&mem[0])))
	})
	if aliasedOffset.err != nil {
		return 0, 0, aliasedOffset.err
	}
	return uintptr(unsafe.Pointer(aliasedOffset.hostPage.Load())), aliasedOffset.guestPage, nil
}

// SetTSCOffset sets the guest TSC offset applied by the platform.
//
// A non-zero offset requires a platform that called EnableGuestAliasedOffset,
// and returns an error otherwise.
//
// SetTSCOffset must be called in host mode, before any clocks are created.
// Changing the offset while clocks exist is not safe: a concurrent reader may
// combine the old and new values.
func SetTSCOffset(offset int64) error {
	if offset == 0 {
		modeOffset.Store(nil)
		tscOffset.Store(0)
		if p := aliasedOffset.hostPage.Load(); p != nil {
			p.Store(0)
		}
		return nil
	}
	p := aliasedOffset.hostPage.Load()
	if p == nil {
		return fmt.Errorf("TSC offset %d requires a platform that supports guest TSC offsetting", offset)
	}
	p.Store(offset)
	// Publish modeOffset last, so that readers observing it also observe
	// tscOffset.
	tscOffset.Store(offset)
	modeOffset.Store(p)
	return nil
}

// TSCOffset returns the current guest TSC offset.
func TSCOffset() int64 {
	return tscOffset.Load()
}

// TSC returns the current value of the TSC in the guest TSC domain.
//
// It may be called in both host and guest mode.
//
// This function is nosplit so that it is not an async preemption point: the
// hardware counter read and the load through modeOffset must execute in the
// same mode, which would not be guaranteed if the goroutine could be
// rescheduled onto a thread in the other mode between them.
//
//go:nosplit
func TSC() TSCValue {
	tsc := Rdtsc()
	if p := modeOffset.Load(); p != nil {
		tsc += TSCValue(p.Load())
	}
	return tsc
}
