// Copyright 2019 The gVisor Authors.
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

// +build arm64

package pagetables

import (
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/sentry/usermem"
)

// archPageTables is architecture-specific data.
type archPageTables struct {
	// root is the pagetable root for kernel space.
	root *PTEs

	// rootPhysical is the cached physical address of the root.
	//
	// This is saved only to prevent constant translation.
	rootPhysical uintptr

	asid uint16
}

// TTBR0_EL1 returns the translation table base register 0.
//
//go:nosplit
func (p *PageTables) TTBR0_EL1(noFlush bool, asid uint16) uint64 {
	return uint64(p.rootPhysical) | (uint64(asid)&ttbrASIDMask)<<ttbrASIDOffset
}

// TTBR1_EL1 returns the translation table base register 1.
//
//go:nosplit
func (p *PageTables) TTBR1_EL1(noFlush bool, asid uint16) uint64 {
	return uint64(p.archPageTables.rootPhysical) | (uint64(asid)&ttbrASIDMask)<<ttbrASIDOffset
}

// Bits in page table entries.
const (
	typeTable   = 0x3 << 0
	typeSect    = 0x1 << 0
	typePage    = 0x3 << 0
	pteValid    = 0x1 << 0
	pteTableBit = 0x1 << 1
	pteTypeMask = 0x3 << 0
	present     = pteValid | pteTableBit
	user        = 0x1 << 6 /* AP[1] */
	readOnly    = 0x1 << 7 /* AP[2] */
	accessed    = 0x1 << 10
	dbm         = 0x1 << 51
	writable    = dbm
	cont        = 0x1 << 52
	pxn         = 0x1 << 53
	xn          = 0x1 << 54
	dirty       = 0x1 << 55
	nG          = 0x1 << 11
	shared      = 0x3 << 8
)

const (
	mtNormal = 0x4 << 2
)

const (
	executeDisable = xn
	optionMask     = 0xfff | 0xfff<<48
	protDefault    = accessed | shared | mtNormal
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

// Clear clears this PTE, including sect page information.
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
// These are all options except Valid and Sect.
//
//go:nosplit
func (p *PTE) Opts() MapOpts {
	v := atomic.LoadUintptr((*uintptr)(p))

	return MapOpts{
		AccessType: usermem.AccessType{
			Read:    true,
			Write:   v&readOnly == 0,
			Execute: v&xn == 0,
		},
		Global: v&nG == 0,
		User:   v&user != 0,
	}
}

// SetSect sets this page as a sect page.
//
// The page must not be valid or a panic will result.
//
//go:nosplit
func (p *PTE) SetSect() {
	if p.Valid() {
		// This is not allowed.
		panic("SetSect called on valid page!")
	}
	atomic.StoreUintptr((*uintptr)(p), typeSect)
}

// IsSect returns true iff this page is a sect page.
//
//go:nosplit
func (p *PTE) IsSect() bool {
	return atomic.LoadUintptr((*uintptr)(p))&pteTypeMask == typeSect
}

// Set sets this PTE value.
//
// This does not change the sect page property.
//
//go:nosplit
func (p *PTE) Set(addr uintptr, opts MapOpts) {
	if !opts.AccessType.Any() {
		p.Clear()
		return
	}
	v := (addr &^ optionMask) | protDefault | nG | readOnly

	if p.IsSect() {
		// Note that this is inherited from the previous instance. Set
		// does not change the value of Sect. See above.
		v |= typeSect
	} else {
		v |= typePage
	}

	if opts.Global {
		v = v &^ nG
	}

	if opts.AccessType.Execute {
		v = v &^ executeDisable
	} else {
		v |= executeDisable
	}
	if opts.AccessType.Write {
		v = v &^ readOnly
	}

	if opts.User {
		v |= user
	} else {
		v = v &^ user
	}
	atomic.StoreUintptr((*uintptr)(p), v)
}

// setPageTable sets this PTE value and forces the write bit and sect bit to
// be cleared. This is used explicitly for breaking sect pages.
//
//go:nosplit
func (p *PTE) setPageTable(pt *PageTables, ptes *PTEs) {
	addr := pt.Allocator.PhysicalFor(ptes)
	if addr&^optionMask != addr {
		// This should never happen.
		panic("unaligned physical address!")
	}
	v := addr | typeTable | protDefault
	atomic.StoreUintptr((*uintptr)(p), v)
}

// Address extracts the address. This should only be used if Valid returns true.
//
//go:nosplit
func (p *PTE) Address() uintptr {
	return atomic.LoadUintptr((*uintptr)(p)) &^ optionMask
}
