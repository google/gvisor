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
)

func TestInit(t *testing.T) {
	// Test that initializing all driverABI works (does not panic or anything).
	Init()
	for _, abi := range abis {
		abi.cons()
	}
}

// TestAllSupportedHashesPresent tests that all the supported versions in nvproxy have hash entries
// in this tool's map. If you're here because of failures run:
// `make sudo TARGETS=//tools/gpu:main ARGS="validate_checksum"`and fix mismatches.
func TestAllSupportedHashesPresent(t *testing.T) {
	Init()
	for version, abi := range abis {
		if abi.checksum == "" {
			t.Errorf("unexpected empty value for driver %q", version.String())
		}
	}
}

// TestABIStructNamesInSync tests that all the supported ioctls in an ABI version are also mapped
// by GetStructNames.
func TestABIStructNamesInSync(t *testing.T) {
	Init()
	for version, abiCons := range abis {
		t.Run(version.String(), func(t *testing.T) {
			abi := abiCons.cons()
			structNames := abi.getStructNames()

			for ioctl := range abi.frontendIoctl {
				if _, ok := structNames.frontendNames[ioctl]; !ok {
					t.Errorf("Frontend ioctl %#x not found in struct names for version %v", ioctl, version.String())
				}
			}
			for ioctl := range abi.uvmIoctl {
				if _, ok := structNames.uvmNames[ioctl]; !ok {
					t.Errorf("UVM ioctl %#x not found in struct names for version %v", ioctl, version.String())
				}
			}
			for ioctl := range abi.controlCmd {
				if _, ok := structNames.controlNames[ioctl]; !ok {
					t.Errorf("Control command %#x not found in struct names for version %v", ioctl, version.String())
				}
			}
			for ioctl := range abi.allocationClass {
				if _, ok := structNames.allocationNames[ioctl]; !ok {
					t.Errorf("Alloc class %#x not found in struct names for version %v", ioctl, version.String())
				}
			}
		})
	}
}
