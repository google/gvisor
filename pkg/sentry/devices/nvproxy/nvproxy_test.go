// Copyright 2023 The gVisor Authors.
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

package nvproxy

import (
	"testing"

	"gvisor.dev/gvisor/pkg/abi/nvgpu"
)

func TestInit(t *testing.T) {
	// Test that initializing all driverABI works (does not panic or anything).
	Init()
	for _, abi := range abis {
		abi.cons()
	}
}

func TestNVOS21ParamsSize(t *testing.T) {
	if nvgpu.SizeofNVOS21ParametersV535 != nvgpu.SizeofNVOS21Parameters {
		// We assume the size of NVOS21_PARAMETERS struct did not change between
		// V525 and V535. If this turns out to be false, a separate seccomp entry
		// needs to be added for the new size value.
		t.Errorf("SizeofNVOS21ParametersV535(%#08x) != SizeofNVOS21Parameters(%#08x)", nvgpu.SizeofNVOS21ParametersV535, nvgpu.SizeofNVOS21Parameters)
	}
}

// TestAllSupportedHashesPresent tests that all the supported versions in nvproxy have hash entries
// in this tool's map. If you're here because of failures run:
// `make sudo TARGETS=//tools/gpu:main ARGS="checksum"`and fix mismatches in supported drivers.
func TestAllSupportedHashesPresent(t *testing.T) {
	Init()
	for version, checksum := range GetSupportedDriversAndChecksums() {
		if checksum == "" {
			t.Errorf("unexpected empty value for driver %q", version.String())
		}
	}
}
