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
