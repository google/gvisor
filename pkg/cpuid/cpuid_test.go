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

package cpuid

import (
	"testing"
)

// These are the default values of various FeatureSet fields.
const (
	defaultVendorID = "GenuineIntel"

	// These processor signature defaults are derived from the values
	// listed in Intel Application Note 485 for i7/Xeon processors.
	defaultExtFamily  uint8 = 0
	defaultExtModel   uint8 = 1
	defaultType       uint8 = 0
	defaultFamily     uint8 = 0x06
	defaultModel      uint8 = 0x0a
	defaultSteppingID uint8 = 0
)

// newEmptyFeatureSet creates a new FeatureSet with a sensible default model and no features.
func newEmptyFeatureSet() *FeatureSet {
	return &FeatureSet{
		Set:            make(map[Feature]bool),
		VendorID:       defaultVendorID,
		ExtendedFamily: defaultExtFamily,
		ExtendedModel:  defaultExtModel,
		ProcessorType:  defaultType,
		Family:         defaultFamily,
		Model:          defaultModel,
		SteppingID:     defaultSteppingID,
	}
}

var justFPU = &FeatureSet{
	Set: map[Feature]bool{
		X86FeatureFPU: true,
	}}

var justFPUandPAE = &FeatureSet{
	Set: map[Feature]bool{
		X86FeatureFPU: true,
		X86FeaturePAE: true,
	}}

func TestSubtract(t *testing.T) {
	if diff := justFPU.Subtract(justFPUandPAE); diff != nil {
		t.Errorf("Got %v is not subset of %v, want diff (%v) to be nil", justFPU, justFPUandPAE, diff)
	}

	if justFPUandPAE.Subtract(justFPU) == nil {
		t.Errorf("Got %v is a subset of %v, want diff to be nil", justFPU, justFPUandPAE)
	}
}

// TODO(b/73346484): Run this test on a very old platform, and make sure more
// bits are enabled than just FPU and PAE. This test currently may not detect
// if HostFeatureSet gives back junk bits.
func TestHostFeatureSet(t *testing.T) {
	hostFeatures := HostFeatureSet()
	if justFPUandPAE.Subtract(hostFeatures) != nil {
		t.Errorf("Got invalid feature set %v from HostFeatureSet()", hostFeatures)
	}
}

func TestHasFeature(t *testing.T) {
	if !justFPU.HasFeature(X86FeatureFPU) {
		t.Errorf("HasFeature failed, %v should contain %v", justFPU, X86FeatureFPU)
	}

	if justFPU.HasFeature(X86FeatureAVX) {
		t.Errorf("HasFeature failed, %v should not contain %v", justFPU, X86FeatureAVX)
	}
}

// Note: these tests are aware of and abuse internal details of FeatureSets.
// Users of FeatureSets should not depend on this.
func TestAdd(t *testing.T) {
	// Test a basic insertion into the FeatureSet.
	testFeatures := newEmptyFeatureSet()
	testFeatures.Add(X86FeatureCLFSH)
	if len(testFeatures.Set) != 1 {
		t.Errorf("Got length %v want 1", len(testFeatures.Set))
	}

	if !testFeatures.HasFeature(X86FeatureCLFSH) {
		t.Errorf("Add failed, got %v want set with %v", testFeatures, X86FeatureCLFSH)
	}

	// Test that duplicates are ignored.
	testFeatures.Add(X86FeatureCLFSH)
	if len(testFeatures.Set) != 1 {
		t.Errorf("Got length %v, want 1", len(testFeatures.Set))
	}
}

func TestRemove(t *testing.T) {
	// Try removing the last feature.
	testFeatures := newEmptyFeatureSet()
	testFeatures.Add(X86FeatureFPU)
	testFeatures.Add(X86FeaturePAE)
	testFeatures.Remove(X86FeaturePAE)
	if !testFeatures.HasFeature(X86FeatureFPU) || len(testFeatures.Set) != 1 || testFeatures.HasFeature(X86FeaturePAE) {
		t.Errorf("Remove failed, got %v want %v", testFeatures, justFPU)
	}

	// Try removing a feature not in the set.
	testFeatures.Remove(X86FeatureRDRAND)
	if !testFeatures.HasFeature(X86FeatureFPU) || len(testFeatures.Set) != 1 {
		t.Errorf("Remove failed, got %v want %v", testFeatures, justFPU)
	}
}

func TestFeatureFromString(t *testing.T) {
	f, ok := FeatureFromString("avx")
	if f != X86FeatureAVX || !ok {
		t.Errorf("got %v want avx", f)
	}

	f, ok = FeatureFromString("bad")
	if ok {
		t.Errorf("got %v want nothing", f)
	}
}

// This tests function 0 (eax=0), which returns the vendor ID and highest cpuid
// function reported to be available.
func TestEmulateIDVendorAndLength(t *testing.T) {
	testFeatures := newEmptyFeatureSet()

	ax, bx, cx, dx := testFeatures.EmulateID(0, 0)
	wantEax := uint32(0xd) // Highest supported cpuid function.

	// These magical constants are the characters of "GenuineIntel".
	// See Intel AN485 for a reference on why they are laid out like this.
	wantEbx := uint32(0x756e6547)
	wantEcx := uint32(0x6c65746e)
	wantEdx := uint32(0x49656e69)
	if wantEax != ax {
		t.Errorf("highest function failed, got %x want %x", ax, wantEax)
	}

	if wantEbx != bx || wantEcx != cx || wantEdx != dx {
		t.Errorf("vendor string emulation failed, bx:cx:dx, got %x:%x:%x want %x:%x:%x", bx, cx, dx, wantEbx, wantEcx, wantEdx)
	}
}

func TestEmulateIDBasicFeatures(t *testing.T) {
	// Make a minimal test feature set.
	testFeatures := newEmptyFeatureSet()
	testFeatures.Add(X86FeatureCLFSH)
	testFeatures.Add(X86FeatureAVX)
	testFeatures.CacheLine = 64

	ax, bx, cx, dx := testFeatures.EmulateID(1, 0)
	ECXAVXBit := uint32(1 << uint(X86FeatureAVX))
	EDXCLFlushBit := uint32(1 << uint(X86FeatureCLFSH-32)) // We adjust by 32 since it's in block 1.

	if EDXCLFlushBit&dx == 0 || dx&^EDXCLFlushBit != 0 {
		t.Errorf("EmulateID failed, got feature bits %x want %x", dx, testFeatures.blockMask(1))
	}

	if ECXAVXBit&cx == 0 || cx&^ECXAVXBit != 0 {
		t.Errorf("EmulateID failed, got feature bits %x want %x", cx, testFeatures.blockMask(0))
	}

	// Default signature bits, based on values for i7/Xeon.
	// See Intel AN485 for information on stepping/model bits.
	defaultSignature := uint32(0x000106a0)
	if defaultSignature != ax {
		t.Errorf("EmulateID stepping emulation failed, got %x want %x", ax, defaultSignature)
	}

	clflushSizeInfo := uint32(8 << 8)
	if clflushSizeInfo != bx {
		t.Errorf("EmulateID bx emulation failed, got %x want %x", bx, clflushSizeInfo)
	}
}

func TestEmulateIDExtendedFeatures(t *testing.T) {
	// Make a minimal test feature set, one bit in each extended feature word.
	testFeatures := newEmptyFeatureSet()
	testFeatures.Add(X86FeatureSMEP)
	testFeatures.Add(X86FeatureAVX512VBMI)

	ax, bx, cx, dx := testFeatures.EmulateID(7, 0)
	EBXSMEPBit := uint32(1 << uint(X86FeatureSMEP-2*32))      // Adjust by 2*32 since SMEP is a block 2 feature.
	ECXAVXBit := uint32(1 << uint(X86FeatureAVX512VBMI-3*32)) // We adjust by 3*32 since it's a block 3 feature.

	// Test that the desired bit is set and no other bits are set.
	if EBXSMEPBit&bx == 0 || bx&^EBXSMEPBit != 0 {
		t.Errorf("extended feature emulation failed, got feature bits %x want %x", bx, testFeatures.blockMask(2))
	}

	if ECXAVXBit&cx == 0 || cx&^ECXAVXBit != 0 {
		t.Errorf("extended feature emulation failed, got feature bits %x want %x", cx, testFeatures.blockMask(3))
	}

	if ax != 0 || dx != 0 {
		t.Errorf("extended feature emulation failed, ax:dx, got %x:%x want 0:0", ax, dx)
	}

	// Check that no subleaves other than 0 do anything.
	ax, bx, cx, dx = testFeatures.EmulateID(7, 1)
	if ax != 0 || bx != 0 || cx != 0 || dx != 0 {
		t.Errorf("extended feature emulation failed, got %x:%x:%x:%x want 0:0", ax, bx, cx, dx)
	}

}

// Checks that the expected extended features are available via cpuid functions
// 0x80000000 and up.
func TestEmulateIDExtended(t *testing.T) {
	testFeatures := newEmptyFeatureSet()
	testFeatures.Add(X86FeatureSYSCALL)
	EDXSYSCALLBit := uint32(1 << uint(X86FeatureSYSCALL-6*32)) // Adjust by 6*32 since SYSCALL is a block 6 feature.

	ax, bx, cx, dx := testFeatures.EmulateID(0x80000000, 0)
	if ax != 0x80000001 || bx != 0 || cx != 0 || dx != 0 {
		t.Errorf("EmulateID extended emulation failed, ax:bx:cx:dx, got %x:%x:%x:%x want 0x80000001:0:0:0", ax, bx, cx, dx)
	}

	_, _, _, dx = testFeatures.EmulateID(0x80000001, 0)
	if EDXSYSCALLBit&dx == 0 || dx&^EDXSYSCALLBit != 0 {
		t.Errorf("extended feature emulation failed, got feature bits %x want %x", dx, testFeatures.blockMask(6))
	}
}
