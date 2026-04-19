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

//go:build riscv64

package cpuid

// FeatureSet for RISC-V is a placeholder.
//
// +stateify savable
type FeatureSet struct {
	hwCap hwCap
}

// HasFeature returns true if the given feature is supported.
func (fs FeatureSet) HasFeature(f Feature) bool {
	return false
}

// HostFeatureSet returns the host feature set.
func HostFeatureSet() FeatureSet {
	return FeatureSet{}
}

// archFlagOrder is a no-op for riscv64.
func archFlagOrder(fn func(Feature)) {}

// archCheckHostCompatible is a noop on riscv64.
func (FeatureSet) archCheckHostCompatible(FeatureSet) error {
	return nil
}

// hostFeatureSet is initialized at startup.
var hostFeatureSet FeatureSet

// archInitialize initializes hostFeatureSet.
func archInitialize() {
	// No-op for riscv64.
}