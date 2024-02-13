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

//go:build amd64
// +build amd64

package cpuid

import (
	"fmt"
	"io"
)

// FeatureSet defines features in terms of CPUID leaves and bits.
// The kernel also exposes the presence of features to userspace through
// a set of flags(HWCAP/HWCAP2) bits, exposed in the auxiliary vector, which
// are necessary to read for some features (e.g. FSGSBASE).
//
// Common references:
//
// Intel:
//   - Intel SDM Volume 2, Chapter 3.2 "CPUID" (more up-to-date)
//   - Intel Application Note 485 (more detailed)
//
// AMD:
//   - AMD64 APM Volume 3, Appendix 3 "Obtaining Processor Information ..."
//
// +stateify savable
type FeatureSet struct {
	// Function is the underlying CPUID Function.
	//
	// This is exported to allow direct calls of the underlying CPUID
	// function, where required.
	Function `state:".(Static)"`
	// hwCap stores HWCAP1/2 exposed from the elf auxiliary vector.
	hwCap hwCap
}

// saveFunction saves the function as a static query.
func (fs *FeatureSet) saveFunction() Static {
	if s, ok := fs.Function.(Static); ok {
		return s
	}
	return fs.ToStatic()
}

// loadFunction saves the function as a static query.
func (fs *FeatureSet) loadFunction(s Static) {
	fs.Function = s
}

// Helper to convert 3 regs into 12-byte vendor ID.
//
//go:nosplit
func vendorIDFromRegs(bx, cx, dx uint32) (r [12]byte) {
	for i := uint(0); i < 4; i++ {
		b := byte(bx >> (i * 8))
		r[i] = b
	}

	for i := uint(0); i < 4; i++ {
		b := byte(dx >> (i * 8))
		r[4+i] = b
	}

	for i := uint(0); i < 4; i++ {
		b := byte(cx >> (i * 8))
		r[8+i] = b
	}

	return r
}

// Helper to merge a 12-byte vendor ID back to registers.
//
// Used by static_amd64.go.
func regsFromVendorID(r [12]byte) (bx, cx, dx uint32) {
	bx |= uint32(r[0])
	bx |= uint32(r[1]) << 8
	bx |= uint32(r[2]) << 16
	bx |= uint32(r[3]) << 24
	cx |= uint32(r[4])
	cx |= uint32(r[5]) << 8
	cx |= uint32(r[6]) << 16
	cx |= uint32(r[7]) << 24
	dx |= uint32(r[8])
	dx |= uint32(r[9]) << 8
	dx |= uint32(r[10]) << 16
	dx |= uint32(r[10]) << 24
	return
}

// VendorID is the 12-char string returned in ebx:edx:ecx for eax=0.
//
//go:nosplit
func (fs FeatureSet) VendorID() [12]byte {
	_, bx, cx, dx := fs.query(vendorID)
	return vendorIDFromRegs(bx, cx, dx)
}

// Helper to deconstruct signature dword.
//
//go:nosplit
func signatureSplit(v uint32) (ef, em, pt, f, m, sid uint8) {
	sid = uint8(v & 0xf)
	m = uint8(v>>4) & 0xf
	f = uint8(v>>8) & 0xf
	pt = uint8(v>>12) & 0x3
	em = uint8(v>>16) & 0xf
	ef = uint8(v >> 20)
	return
}

// ExtendedFamily is part of the processor signature.
//
//go:nosplit
func (fs FeatureSet) ExtendedFamily() uint8 {
	ax, _, _, _ := fs.query(featureInfo)
	ef, _, _, _, _, _ := signatureSplit(ax)
	return ef
}

// ExtendedModel is part of the processor signature.
//
//go:nosplit
func (fs FeatureSet) ExtendedModel() uint8 {
	ax, _, _, _ := fs.query(featureInfo)
	_, em, _, _, _, _ := signatureSplit(ax)
	return em
}

// ProcessorType is part of the processor signature.
//
//go:nosplit
func (fs FeatureSet) ProcessorType() uint8 {
	ax, _, _, _ := fs.query(featureInfo)
	_, _, pt, _, _, _ := signatureSplit(ax)
	return pt
}

// Family is part of the processor signature.
//
//go:nosplit
func (fs FeatureSet) Family() uint8 {
	ax, _, _, _ := fs.query(featureInfo)
	_, _, _, f, _, _ := signatureSplit(ax)
	return f
}

// Model is part of the processor signature.
//
//go:nosplit
func (fs FeatureSet) Model() uint8 {
	ax, _, _, _ := fs.query(featureInfo)
	_, _, _, _, m, _ := signatureSplit(ax)
	return m
}

// SteppingID is part of the processor signature.
//
//go:nosplit
func (fs FeatureSet) SteppingID() uint8 {
	ax, _, _, _ := fs.query(featureInfo)
	_, _, _, _, _, sid := signatureSplit(ax)
	return sid
}

// VirtualAddressBits returns the number of bits available for virtual
// addresses.
//
//go:nosplit
func (fs FeatureSet) VirtualAddressBits() uint32 {
	ax, _, _, _ := fs.query(addressSizes)
	return (ax >> 8) & 0xff
}

// PhysicalAddressBits returns the number of bits available for physical
// addresses.
//
//go:nosplit
func (fs FeatureSet) PhysicalAddressBits() uint32 {
	ax, _, _, _ := fs.query(addressSizes)
	return ax & 0xff
}

// CacheType describes the type of a cache, as returned in eax[4:0] for eax=4.
type CacheType uint8

const (
	// cacheNull indicates that there are no more entries.
	cacheNull CacheType = iota

	// CacheData is a data cache.
	CacheData

	// CacheInstruction is an instruction cache.
	CacheInstruction

	// CacheUnified is a unified instruction and data cache.
	CacheUnified
)

// Cache describes the parameters of a single cache on the system.
//
// This is returned by the Caches method on FeatureSet.
type Cache struct {
	// Level is the hierarchical level of this cache (L1, L2, etc).
	Level uint32

	// Type is the type of cache.
	Type CacheType

	// FullyAssociative indicates that entries may be placed in any block.
	FullyAssociative bool

	// Partitions is the number of physical partitions in the cache.
	Partitions uint32

	// Ways is the number of ways of associativity in the cache.
	Ways uint32

	// Sets is the number of sets in the cache.
	Sets uint32

	// InvalidateHierarchical indicates that WBINVD/INVD from threads
	// sharing this cache acts upon lower level caches for threads sharing
	// this cache.
	InvalidateHierarchical bool

	// Inclusive indicates that this cache is inclusive of lower cache
	// levels.
	Inclusive bool

	// DirectMapped indicates that this cache is directly mapped from
	// address, rather than using a hash function.
	DirectMapped bool
}

// Caches describes the caches on the CPU.
//
// Only supported on Intel; requires allocation.
func (fs FeatureSet) Caches() (caches []Cache) {
	if !fs.Intel() {
		return
	}
	// Check against the cache line, which should be consistent.
	cacheLine := fs.CacheLine()
	for i := uint32(0); ; i++ {
		out := fs.Query(In{
			Eax: uint32(intelDeterministicCacheParams),
			Ecx: i,
		})
		t := CacheType(out.Eax & 0xf)
		if t == cacheNull {
			break
		}
		lineSize := (out.Ebx & 0xfff) + 1
		if lineSize != cacheLine {
			panic(fmt.Sprintf("Mismatched cache line size: %d vs %d", lineSize, cacheLine))
		}
		caches = append(caches, Cache{
			Type:                   t,
			Level:                  (out.Eax >> 5) & 0x7,
			FullyAssociative:       ((out.Eax >> 9) & 1) == 1,
			Partitions:             ((out.Ebx >> 12) & 0x3ff) + 1,
			Ways:                   ((out.Ebx >> 22) & 0x3ff) + 1,
			Sets:                   out.Ecx + 1,
			InvalidateHierarchical: (out.Edx & 1) == 0,
			Inclusive:              ((out.Edx >> 1) & 1) == 1,
			DirectMapped:           ((out.Edx >> 2) & 1) == 0,
		})
	}
	return
}

// CacheLine is the size of a cache line in bytes.
//
// All caches use the same line size. This is not enforced in the CPUID
// encoding, but is true on all known x86 processors.
//
//go:nosplit
func (fs FeatureSet) CacheLine() uint32 {
	_, bx, _, _ := fs.query(featureInfo)
	return 8 * (bx >> 8) & 0xff
}

// HasFeature tests whether or not a feature is in the given feature set.
//
// This function is safe to call from a nosplit context, as long as the
// FeatureSet does not have any masked features.
//
//go:nosplit
func (fs FeatureSet) HasFeature(feature Feature) bool {
	return feature.check(fs)
}

// WriteCPUInfoTo is to generate a section of one cpu in /proc/cpuinfo. This is
// a minimal /proc/cpuinfo, it is missing some fields like "microcode" that are
// not always printed in Linux. The bogomips field is simply made up.
func (fs FeatureSet) WriteCPUInfoTo(cpu uint, w io.Writer) {
	// Avoid many redundant calls here, since this can occasionally appear
	// in the hot path. Read all basic information up front, see above.
	ax, _, _, _ := fs.query(featureInfo)
	ef, em, _, f, m, _ := signatureSplit(ax)
	vendor := fs.VendorID()
	fmt.Fprintf(w, "processor\t: %d\n", cpu)
	fmt.Fprintf(w, "vendor_id\t: %s\n", string(vendor[:]))
	fmt.Fprintf(w, "cpu family\t: %d\n", ((ef<<4)&0xff)|f)
	fmt.Fprintf(w, "model\t\t: %d\n", ((em<<4)&0xff)|m)
	fmt.Fprintf(w, "model name\t: %s\n", "unknown") // Unknown for now.
	fmt.Fprintf(w, "stepping\t: %s\n", "unknown")   // Unknown for now.
	fmt.Fprintf(w, "cpu MHz\t\t: %.3f\n", cpuFreqMHz)
	fmt.Fprintf(w, "fpu\t\t: yes\n")
	fmt.Fprintf(w, "fpu_exception\t: yes\n")
	fmt.Fprintf(w, "cpuid level\t: %d\n", uint32(xSaveInfo)) // Same as ax in vendorID.
	fmt.Fprintf(w, "wp\t\t: yes\n")
	fmt.Fprintf(w, "flags\t\t: %s\n", fs.FlagString())
	fmt.Fprintf(w, "bogomips\t: %.02f\n", cpuFreqMHz) // It's bogus anyway.
	fmt.Fprintf(w, "clflush size\t: %d\n", fs.CacheLine())
	fmt.Fprintf(w, "cache_alignment\t: %d\n", fs.CacheLine())
	fmt.Fprintf(w, "address sizes\t: %d bits physical, %d bits virtual\n", 46, 48)
	fmt.Fprintf(w, "power management:\n") // This is always here, but can be blank.
	fmt.Fprintf(w, "\n")                  // The /proc/cpuinfo file ends with an extra newline.
}

var (
	authenticAMD = [12]byte{'A', 'u', 't', 'h', 'e', 'n', 't', 'i', 'c', 'A', 'M', 'D'}
	genuineIntel = [12]byte{'G', 'e', 'n', 'u', 'i', 'n', 'e', 'I', 'n', 't', 'e', 'l'}
)

// AMD returns true if fs describes an AMD CPU.
//
//go:nosplit
func (fs FeatureSet) AMD() bool {
	return fs.VendorID() == authenticAMD
}

// Intel returns true if fs describes an Intel CPU.
//
//go:nosplit
func (fs FeatureSet) Intel() bool {
	return fs.VendorID() == genuineIntel
}

// Leaf 0 of xsaveinfo function returns the size for currently
// enabled xsave features in ebx, the maximum size if all valid
// features are saved with xsave in ecx, and valid XCR0 bits in
// edx:eax.
//
// If xSaveInfo isn't supported, cpuid will not fault but will
// return bogus values.
var (
	xsaveSize       = native(In{Eax: uint32(xSaveInfo)}).Ebx
	maxXsaveSize    = native(In{Eax: uint32(xSaveInfo)}).Ecx
	amxTileCfgSize  = native(In{Eax: uint32(xSaveInfo), Ecx: 17}).Eax
	amxTileDataSize = native(In{Eax: uint32(xSaveInfo), Ecx: 18}).Eax
)

const (
	// XCR0AMXMask are the bits that enable xsave to operate on AMX TILECFG
	// and TILEDATA.
	//
	// Note: TILECFG and TILEDATA are always either both enabled or both
	//       disabled.
	//
	// See Intel® 64 and IA-32 Architectures Software Developer’s Manual Vol.1
	// section 13.3 for details.
	XCR0AMXMask = uint64((1 << 17) | (1 << 18))
)

// ExtendedStateSize returns the number of bytes needed to save the "extended
// state" for the enabled features and the boundary it must be aligned to.
// Extended state includes floating point registers, and other cpu state that's
// not associated with the normal task context.
//
// Note: the return value matches the size of signal FP state frames.
// Look at check_xstate_in_sigframe() in the kernel sources for more details.
//
//go:nosplit
func (fs FeatureSet) ExtendedStateSize() (size, align uint) {
	if fs.UseXsave() {
		return uint(xsaveSize), 64
	}

	// If we don't support xsave, we fall back to fxsave, which requires
	// 512 bytes aligned to 16 bytes.
	return 512, 16
}

// AMXExtendedStateSize returns the number of bytes within the "extended state"
// area that is used for AMX.
func (fs FeatureSet) AMXExtendedStateSize() uint {
	if fs.UseXsave() {
		xcr0 := xgetbv(0)
		if (xcr0 & XCR0AMXMask) != 0 {
			return uint(amxTileCfgSize + amxTileDataSize)
		}
	}
	return 0
}

// ValidXCR0Mask returns the valid bits in control register XCR0.
//
// Always exclude AMX bits, because we do not support it.
// TODO(gvisor.dev/issues/9896): Implement AMX Support.
//
//go:nosplit
func (fs FeatureSet) ValidXCR0Mask() uint64 {
	if !fs.HasFeature(X86FeatureXSAVE) {
		return 0
	}
	ax, _, _, dx := fs.query(xSaveInfo)
	return (uint64(dx)<<32 | uint64(ax)) &^ XCR0AMXMask
}

// UseXsave returns the choice of fp state saving instruction.
//
//go:nosplit
func (fs FeatureSet) UseXsave() bool {
	return fs.HasFeature(X86FeatureXSAVE) && fs.HasFeature(X86FeatureOSXSAVE)
}

// UseXsaveopt returns true if 'fs' supports the "xsaveopt" instruction.
//
//go:nosplit
func (fs FeatureSet) UseXsaveopt() bool {
	return fs.UseXsave() && fs.HasFeature(X86FeatureXSAVEOPT)
}

// UseXsavec returns true if 'fs' supports the "xsavec" instruction.
//
//go:nosplit
func (fs FeatureSet) UseXsavec() bool {
	return fs.UseXsaveopt() && fs.HasFeature(X86FeatureXSAVEC)
}

// UseFSGSBASE returns true if 'fs' supports the (RD|WR)(FS|GS)BASE instructions.
func (fs FeatureSet) UseFSGSBASE() bool {
	HWCAP2_FSGSBASE := uint64(1) << 1
	return fs.HasFeature(X86FeatureFSGSBase) && ((fs.hwCap.hwCap2 & HWCAP2_FSGSBASE) != 0)
}

// archCheckHostCompatible checks for compatibility.
func (fs FeatureSet) archCheckHostCompatible(hfs FeatureSet) error {
	// The size of a cache line must match, as it is critical to correctly
	// utilizing CLFLUSH. Other cache properties are allowed to change, as
	// they are not important to correctness.
	fsCache := fs.CacheLine()
	hostCache := hfs.CacheLine()
	if fsCache != hostCache {
		return &ErrIncompatible{
			reason: fmt.Sprintf("CPU cache line size %d incompatible with host cache line size %d", fsCache, hostCache),
		}
	}

	return nil
}
