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

// +build i386 amd64

package pagetables

import (
	"sync/atomic"

	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
)

// Opts are pagetable options.
type Opts struct {
	EnablePCID bool
}

// archPageTables has x86-specific features.
type archPageTables struct {
	// pcids is the PCID database.
	pcids *PCIDs

	// pcid is the globally unique identifier, or zero if none were
	// available or pcids is nil.
	pcid uint16
}

// init initializes arch-specific features.
func (a *archPageTables) init(opts Opts) {
	if opts.EnablePCID {
		a.pcids = NewPCIDs()
		a.pcid = a.pcids.allocate()
	}
}

// initFrom initializes arch-specific features from an existing entry.'
func (a *archPageTables) initFrom(other *archPageTables) {
	a.pcids = other.pcids // Refer to the same PCID database.
	if a.pcids != nil {
		a.pcid = a.pcids.allocate()
	}
}

// release is called from Release.
func (a *archPageTables) release() {
	// Return the PCID.
	if a.pcids != nil {
		a.pcids.free(a.pcid)
	}
}

// CR3 returns the CR3 value for these tables.
//
// This may be called in interrupt contexts.
//
//go:nosplit
func (p *PageTables) CR3() uint64 {
	// Bit 63 is set to avoid flushing the PCID (per SDM 4.10.4.1).
	const noFlushBit uint64 = 0x8000000000000000
	if p.pcid != 0 {
		return noFlushBit | uint64(p.root.physical) | uint64(p.pcid)
	}
	return uint64(p.root.physical)
}

// FlushCR3 returns the CR3 value that flushes the TLB.
//
// This may be called in interrupt contexts.
//
//go:nosplit
func (p *PageTables) FlushCR3() uint64 {
	return uint64(p.root.physical) | uint64(p.pcid)
}

// Bits in page table entries.
const (
	present      = 0x001
	writable     = 0x002
	user         = 0x004
	writeThrough = 0x008
	cacheDisable = 0x010
	accessed     = 0x020
	dirty        = 0x040
	super        = 0x080
	global       = 0x100
	optionMask   = executeDisable | 0xfff
)

// MapOpts are x86 options.
type MapOpts struct {
	// AccessType defines permissions.
	AccessType usermem.AccessType

	// Global indicates the page is globally accessible.
	Global bool

	// User indicates the page is a user page.
	User bool
}

// PTE is a page table entry.
type PTE uintptr

// Clear clears this PTE, including super page information.
//
//go:nosplit
func (p *PTE) Clear() {
	atomic.StoreUintptr((*uintptr)(p), 0)
}

// Valid returns true iff this entry is valid.
//
//go:nosplit
func (p *PTE) Valid() bool {
	return atomic.LoadUintptr((*uintptr)(p))&present != 0
}

// Opts returns the PTE options.
//
// These are all options except Valid and Super.
//
//go:nosplit
func (p *PTE) Opts() MapOpts {
	v := atomic.LoadUintptr((*uintptr)(p))
	return MapOpts{
		AccessType: usermem.AccessType{
			Read:    v&present != 0,
			Write:   v&writable != 0,
			Execute: v&executeDisable == 0,
		},
		Global: v&global != 0,
		User:   v&user != 0,
	}
}

// SetSuper sets this page as a super page.
//
// The page must not be valid or a panic will result.
//
//go:nosplit
func (p *PTE) SetSuper() {
	if p.Valid() {
		// This is not allowed.
		panic("SetSuper called on valid page!")
	}
	atomic.StoreUintptr((*uintptr)(p), super)
}

// IsSuper returns true iff this page is a super page.
//
//go:nosplit
func (p *PTE) IsSuper() bool {
	return atomic.LoadUintptr((*uintptr)(p))&super != 0
}

// Set sets this PTE value.
//
// This does not change the super page property.
//
//go:nosplit
func (p *PTE) Set(addr uintptr, opts MapOpts) {
	if !opts.AccessType.Any() {
		p.Clear()
		return
	}
	v := (addr &^ optionMask) | present | accessed
	if opts.User {
		v |= user
	}
	if opts.Global {
		v |= global
	}
	if !opts.AccessType.Execute {
		v |= executeDisable
	}
	if opts.AccessType.Write {
		v |= writable | dirty
	}
	if p.IsSuper() {
		// Note that this is inherited from the previous instance. Set
		// does not change the value of Super. See above.
		v |= super
	}
	atomic.StoreUintptr((*uintptr)(p), v)
}

// setPageTable sets this PTE value and forces the write bit and super bit to
// be cleared. This is used explicitly for breaking super pages.
//
//go:nosplit
func (p *PTE) setPageTable(addr uintptr) {
	v := (addr &^ optionMask) | present | user | writable | accessed | dirty
	atomic.StoreUintptr((*uintptr)(p), v)
}

// Address extracts the address. This should only be used if Valid returns true.
//
//go:nosplit
func (p *PTE) Address() uintptr {
	return atomic.LoadUintptr((*uintptr)(p)) &^ optionMask
}
