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

// Package cpuid provides basic functionality for creating and adjusting CPU
// feature sets.
//
// To use FeatureSets, one should start with an existing FeatureSet (either a
// known platform, or HostFeatureSet()) and then add, remove, and test for
// features as desired.
//
// For example: on x86, test for hardware extended state saving, and if
// we don't have it, don't expose AVX, which cannot be saved with fxsave.
//
//   if !HostFeatureSet().HasFeature(X86FeatureXSAVE) {
//     exposedFeatures.Remove(X86FeatureAVX)
//   }
package cpuid

// Feature is a unique identifier for a particular cpu feature. We just use an
// int as a feature number on x86 and arm64.
//
// On x86, features are numbered according to "blocks". Each block is 32 bits, and
// feature bits from the same source (cpuid leaf/level) are in the same block.
//
// On arm64, features are numbered according to the ELF HWCAP definition.
// arch/arm64/include/uapi/asm/hwcap.h
type Feature int

// HostFeatureSet returns a FeatureSet that matches that of the host machine.
// Callers must not mutate the returned FeatureSet.
func HostFeatureSet() *FeatureSet {
	return hostFeatureSet
}

var hostFeatureSet *FeatureSet

// ErrIncompatible is returned by FeatureSet.HostCompatible if fs is not a
// subset of the host feature set.
type ErrIncompatible struct {
	message string
}

// Error implements error.
func (e ErrIncompatible) Error() string {
	return e.message
}
