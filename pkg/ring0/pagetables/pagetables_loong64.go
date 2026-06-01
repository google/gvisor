// Copyright 2024 The gVisor Authors.
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

//go:build loong64
// +build loong64

// LoongArch64 minimal stubs for ring0/pagetables. The ptrace platform
// does not maintain its own page tables, so this package is never
// exercised at runtime.

package pagetables

import "gvisor.dev/gvisor/pkg/hostarch"

// PTE is the page-table entry type for LoongArch64. Empty stub.
type PTE uint64

// archPageTables holds architecture-specific page-table state.
//
// +stateify savable
type archPageTables struct{}

// InitArch is a no-op on LoongArch64.
func (p *PageTables) InitArch(allocator Allocator) {}


// entriesPerPage is the number of PTE entries per page on LoongArch
// with 16K pages and 8-byte PTEs (16384 / 8 = 2048). This matches the
// number the ptrace platform never actually consults but the type must
// exist for pagetables.go to compile.
const entriesPerPage = 2048

// PTEs is a set of PTE entries forming one page-table level.
type PTEs [entriesPerPage]PTE

// MapOpts mirror the x86 / aarch64 shape so the generic pagetables.go
// code compiles. The fields are unused on LoongArch (ptrace platform).
type MapOpts struct {
	AccessType hostarch.AccessType
	Global     bool
	User       bool
	MemoryType hostarch.MemoryType
}

// The four walkers below are stubs of the templates that walker_generic.go
// is instantiated into on amd64 / arm64. The ptrace platform never calls
// iterateRange on LoongArch, so they intentionally do nothing.

type mapWalker struct {
	pageTables *PageTables
	visitor    mapVisitor
}

func (w *mapWalker) iterateRange(start, end uintptr) {}

type unmapWalker struct {
	pageTables *PageTables
	visitor    unmapVisitor
}

func (w *unmapWalker) iterateRange(start, end uintptr) {}

type emptyWalker struct {
	pageTables *PageTables
	visitor    emptyVisitor
}

func (w *emptyWalker) iterateRange(start, end uintptr) {}

type lookupWalker struct {
	pageTables *PageTables
	visitor    lookupVisitor
}

func (w *lookupWalker) iterateRange(start, end uintptr) {}

// PTE method stubs. These compile-only; the ptrace platform never
// dereferences a PTE on LoongArch.

// Valid returns true if the PTE refers to a mapped page.
func (p *PTE) Valid() bool { return false }

// Address returns the physical address tracked by this PTE.
func (p *PTE) Address() uintptr { return 0 }

// Opts returns the MapOpts encoded in this PTE.
func (p *PTE) Opts() MapOpts { return MapOpts{} }

// Set rewrites the PTE to point at addr with the given options.
func (p *PTE) Set(addr uintptr, opts MapOpts) {}

// SetSect is a no-op on LoongArch.
func (p *PTE) SetSect() {}

// Clear zeroes the PTE.
func (p *PTE) Clear() { *p = 0 }

// IsSect reports whether this PTE is a section / huge mapping.
func (p *PTE) IsSect() bool { return false }

// LoongArch placeholder constants for the generic walker. The ptrace
// platform never invokes the walker on LoongArch; these values exist so
// pagetables.go and walker_generic.go compile.
const (
	pteSize     = 1 << 12
	lowerTop    uintptr = 1 << 47
	upperBottom uintptr = 1 << 48
)

// iterateRangeCanonical is a no-op stub. ring0 is unused on LoongArch.
//
//go:nosplit
func (w *Walker) iterateRangeCanonical(start, end uintptr) bool { return true }

// limitPCID is the maximum PCID value. Unused on LoongArch — the LoongArch
// TLB ASID is 10 bits, but the value is reserved here only so pcids.go
// (which references limitPCID at package level) compiles.
const limitPCID uint16 = 1023
