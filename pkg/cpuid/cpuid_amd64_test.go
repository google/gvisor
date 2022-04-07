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
	"testing"
)

// makeFatureSet creates a new FeatureSet.
func makeFeatureSet(features ...Feature) FeatureSet {
	s := make(Static)
	for _, f := range features {
		s.Add(f)
	}
	return FeatureSet{
		Function: s,
	}
}

var (
	justFPU       = makeFeatureSet(X86FeatureFPU)
	justFPUandPAE = makeFeatureSet(X86FeatureFPU, X86FeaturePAE)
)

func TestSubtract(t *testing.T) {
	if left := justFPU.Subtract(justFPUandPAE); len(left) > 0 {
		t.Errorf("Got %q is not subset of %q, want left (%v) to be non-empty", justFPU.FlagString(), justFPUandPAE.FlagString(), left)
	}
	if left := justFPUandPAE.Subtract(justFPU); len(left) == 0 {
		t.Errorf("Got %q is a subset of %q, want left (%v) to be empty", justFPU.FlagString(), justFPUandPAE.FlagString(), left)
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

func TestFixedExtendedState(t *testing.T) {
	hostFeatures := HostFeatureSet()
	fixedFeatures := hostFeatures.Fixed()
	for i, allowed := range allowedBasicFunctions {
		if !allowed {
			continue
		}
		in := In{Eax: uint32(i) + uint32(extendedStart)}
		h := hostFeatures.Query(in)
		f := fixedFeatures.Query(in)
		if h != f {
			t.Errorf("native: %x fixed: %x", h, f)
		}
	}

}

func TestHasFeature(t *testing.T) {
	if !justFPU.HasFeature(X86FeatureFPU) {
		t.Errorf("HasFeature failed, %q should contain %v", justFPU.FlagString(), X86FeatureFPU)
	}
	if justFPU.HasFeature(X86FeatureAVX) {
		t.Errorf("HasFeature failed, %q should not contain %v", justFPU.FlagString(), X86FeatureAVX)
	}
}

func TestAdd(t *testing.T) {
	// Test a basic insertion into the FeatureSet.
	testFeatures := makeFeatureSet(X86FeatureCLFSH)
	if !testFeatures.HasFeature(X86FeatureCLFSH) {
		t.Errorf("Add failed, got %v want set with %v", testFeatures, X86FeatureCLFSH)
	}

	// Test that duplicates are ignored.
	testFeatures.Function.(Static).Add(X86FeatureCLFSH)
	if !testFeatures.HasFeature(X86FeatureCLFSH) {
		t.Errorf("Duplicate add removed entry, got %v want set with %v", testFeatures, X86FeatureCLFSH)
	}
}

func TestRemove(t *testing.T) {
	// Try removing the last feature.
	testFeatures := makeFeatureSet(X86FeatureFPU, X86FeaturePAE)
	testFeatures.Function.(Static).Remove(X86FeaturePAE)
	if !testFeatures.HasFeature(X86FeatureFPU) || testFeatures.HasFeature(X86FeaturePAE) {
		t.Errorf("Remove failed, got %q want %q", testFeatures.FlagString(), justFPU.FlagString())
	}

	// Try removing a feature not in the set.
	testFeatures.Function.(Static).Remove(X86FeatureRDRAND)
	if !testFeatures.HasFeature(X86FeatureFPU) {
		t.Errorf("Remove failed, got %q want %q", testFeatures.FlagString(), justFPU.FlagString())
	}
}
