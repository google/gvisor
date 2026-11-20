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

//go:build arm64
// +build arm64

package kernel

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/cpuid"
)

// syncFPStateSize is a no-op on arm64, which has no dynamic XSAVE features.
func (t *Task) syncFPStateSize() bool {
	return true
}

// fpStateNeedsResize returns false on arm64, which has no dynamic XSAVE
// features.
func (t *Task) fpStateNeedsResize() bool {
	return false
}

// signalStackTooSmall returns false on arm64, which has no dynamic XSAVE
// features.
func (k *Kernel) signalStackTooSmall(alt linux.SignalStack, perm uint64) bool {
	return false
}

// featureSetForPlatform returns k's feature set.
func (k *Kernel) featureSetForPlatform() cpuid.FeatureSet {
	return k.featureSet
}

// hideUnsupportedAMX is a no-op on arm64, which has no AMX.
func (k *Kernel) hideUnsupportedAMX() error {
	return nil
}

// syncRestoredFPStateSizes is a no-op on arm64, which has no dynamic XSAVE
// features.
func (k *Kernel) syncRestoredFPStateSizes() {}
