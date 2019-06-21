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

package auth

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/bits"
)

// A CapabilitySet is a set of capabilities implemented as a bitset. The zero
// value of CapabilitySet is a set containing no capabilities.
type CapabilitySet uint64

// AllCapabilities is a CapabilitySet containing all valid capabilities.
var AllCapabilities = CapabilitySetOf(linux.CAP_LAST_CAP+1) - 1

// CapabilitySetOf returns a CapabilitySet containing only the given
// capability.
func CapabilitySetOf(cp linux.Capability) CapabilitySet {
	return CapabilitySet(bits.MaskOf64(int(cp)))
}

// CapabilitySetOfMany returns a CapabilitySet containing the given capabilities.
func CapabilitySetOfMany(cps []linux.Capability) CapabilitySet {
	var cs uint64
	for _, cp := range cps {
		cs |= bits.MaskOf64(int(cp))
	}
	return CapabilitySet(cs)
}

// TaskCapabilities represents all the capability sets for a task. Each of these
// sets is explained in greater detail in capabilities(7).
type TaskCapabilities struct {
	// Permitted is a limiting superset for the effective capabilities that
	// the thread may assume.
	PermittedCaps CapabilitySet
	// Inheritable is a set of capabilities preserved across an execve(2).
	InheritableCaps CapabilitySet
	// Effective is the set of capabilities used by the kernel to perform
	// permission checks for the thread.
	EffectiveCaps CapabilitySet
	// Bounding is a limiting superset for the capabilities that a thread
	// can add to its inheritable set using capset(2).
	BoundingCaps CapabilitySet
	// Ambient is a set of capabilities that are preserved across an
	// execve(2) of a program that is not privileged.
	AmbientCaps CapabilitySet
}
