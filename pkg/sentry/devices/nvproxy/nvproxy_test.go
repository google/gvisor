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
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/nvgpu"
	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/pkg/sentry/devices/nvproxy/nvconf"
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
			structNames := abi.getStructs()

			for ioctl := range abi.frontendIoctl {
				if _, ok := structNames.frontendStructs[ioctl]; !ok {
					t.Errorf("Frontend ioctl %#x not found in struct names for version %v", ioctl, version.String())
				}
			}
			for ioctl := range abi.uvmIoctl {
				if _, ok := structNames.uvmStructs[ioctl]; !ok {
					t.Errorf("UVM ioctl %#x not found in struct names for version %v", ioctl, version.String())
				}
			}
			for ioctl := range abi.controlCmd {
				if _, ok := structNames.controlStructs[ioctl]; !ok {
					t.Errorf("Control command %#x not found in struct names for version %v", ioctl, version.String())
				}
			}
			for ioctl := range abi.allocationClass {
				if _, ok := structNames.allocationStructs[ioctl]; !ok {
					t.Errorf("Alloc class %#x not found in struct names for version %v", ioctl, version.String())
				}
			}
		})
	}
}

// testHandler is a helper function to test an ioctl handler type.
// `handleFn` must call the `Handler`'s `handle` method with the given `Input`.
// `validHandler` must accept `CapCompute` and return 42.
// `validInput` must be a valid input for the handler that enables `CapCompute`.
// `invalidInput` must not enable `CapCompute`.
func testHandler[Handler, Input any](
	t *testing.T,
	handleFn func(Handler, Input) (uintptr, error),
	validHandler Handler,
	validInput, invalidInput Input,
) {
	t.Helper()
	for _, test := range []struct {
		name       string
		handler    Handler
		input      Input
		wantResult uintptr
		wantErr    error
	}{
		{
			name:       "valid",
			handler:    validHandler,
			input:      validInput,
			wantResult: 42,
		},
		{
			name:    "undefined handler",
			wantErr: &errUndefinedHandler,
		},
		{
			name:    "missing capability",
			handler: validHandler,
			input:   invalidInput,
			wantErr: &errMissingCapability,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := handleFn(test.handler, test.input)
			if err != test.wantErr {
				t.Errorf("handle returned err=%v wantErr=%t", err, test.wantErr)
			}
			if got != test.wantResult {
				t.Errorf("handle returned got=%v want=%v", got, test.wantResult)
			}
		})
	}
}

func TestHandlers(t *testing.T) {
	capComputeNVP := &nvproxy{
		capsEnabled: nvconf.CapCompute,
	}
	capComputeState := &frontendIoctlState{
		fd: &frontendFD{
			dev: &frontendDevice{nvp: capComputeNVP},
		},
	}
	capUtilityNVP := &nvproxy{
		capsEnabled: nvconf.CapUtility,
	}
	capUtilityState := &frontendIoctlState{
		fd: &frontendFD{
			dev: &frontendDevice{nvp: capUtilityNVP},
		},
	}
	capCompute := nvconf.CapCompute
	t.Run("frontend", func(t *testing.T) {
		testHandler(
			t,
			func(handler frontendIoctlHandler, fi *frontendIoctlState) (uintptr, error) {
				return handler.handle(fi)
			},
			feHandler(func(*frontendIoctlState) (uintptr, error) {
				return 42, nil
			}, capCompute),
			capComputeState,
			capUtilityState,
		)
	})
	t.Run("control command", func(t *testing.T) {
		type controlCmdInput struct {
			fi     *frontendIoctlState
			params *nvgpu.NVOS54_PARAMETERS
		}
		testHandler(
			t,
			func(handler controlCmdHandler, input controlCmdInput) (uintptr, error) {
				return handler.handle(input.fi, input.params)
			},
			ctrlHandler(func(*frontendIoctlState, *nvgpu.NVOS54_PARAMETERS) (uintptr, error) {
				return 42, nil
			}, capCompute),
			controlCmdInput{fi: capComputeState},
			controlCmdInput{fi: capUtilityState},
		)
	})
	t.Run("allocation class", func(t *testing.T) {
		type allocClassInput struct {
			fi          *frontendIoctlState
			ioctlParams *nvgpu.NVOS64_PARAMETERS
			isNVOS64    bool
		}
		testHandler(
			t,
			func(handler allocationClassHandler, input allocClassInput) (uintptr, error) {
				return handler.handle(input.fi, input.ioctlParams, input.isNVOS64)
			},
			allocHandler(func(*frontendIoctlState, *nvgpu.NVOS64_PARAMETERS, bool) (uintptr, error) {
				return 42, nil
			}, capCompute),
			allocClassInput{fi: capComputeState},
			allocClassInput{fi: capUtilityState},
		)
	})
	t.Run("uvm", func(t *testing.T) {
		testHandler(
			t,
			func(handler uvmIoctlHandler, ui *uvmIoctlState) (uintptr, error) {
				return handler.handle(ui)
			},
			uvmHandler(func(*uvmIoctlState) (uintptr, error) {
				return 42, nil
			}, capCompute),
			&uvmIoctlState{
				fd: &uvmFD{
					dev: &uvmDevice{nvp: capComputeNVP},
				},
			},
			&uvmIoctlState{
				fd: &uvmFD{
					dev: &uvmDevice{nvp: capUtilityNVP},
				},
			},
		)
	})
}

// TestFilterCapabilities loosely verifies that the seccomp filters have the
// expected number of entries relative to the capabilities that are enabled
// by comparing them against what the ABI handlers would suggest.
// This also acts as a useful reminder to keep the seccomp filters in sync
// with the ABI handers.
func TestFilterCapabilities(t *testing.T) {
	var (
		// Set of frontend ioctls that nvproxy accepts but does not forward to the
		// host.
		nonForwardedFrontendIoctls = map[uint32]struct{}{
			nvgpu.NV_ESC_NUMA_INFO: struct{}{},
		}

		// Set of frontend ioctls that nvproxy makes but does not accept from the
		// application.
		nvproxyOnlyFrontendIoctls = map[uint32]struct{}{ /* Empty right now. */ }

		// Set of UVM ioctls that nvproxy accepts but does not forward to the host.
		nonForwardedUVMIoctls = map[uint32]struct{}{ /* Empty right now. */ }

		// Set of UVM ioctls that nvproxy makes but does not accept from the
		// application.
		nvproxyOnlyUVMIoctls = map[uint32]struct{}{
			// UVM_TOOLS_READ_PROCESS_MEMORY is manually invoked by
			// nvproxy when handling reads for UVM memory-mapped data.
			nvgpu.UVM_TOOLS_READ_PROCESS_MEMORY: struct{}{},
			// Similar deal for writing to UVM memory-mapped data.
			nvgpu.UVM_TOOLS_WRITE_PROCESS_MEMORY: struct{}{},
		}
	)

	// Build list of interesting capability sets.
	capSets := []nvconf.DriverCaps{
		0,
		nvconf.ValidCapabilities,
		nvconf.SupportedDriverCaps,
		nvconf.DefaultDriverCaps,
	}
	for _, capName := range strings.Split(nvconf.ValidCapabilities.String(), ",") {
		individualCap, _, err := nvconf.DriverCapsFromString(capName)
		if err != nil {
			t.Fatalf("nvconf.DriverCapsFromString(%q) failed: %v", capName, err)
		}
		capSets = append(capSets, individualCap)
	}
	for _, capSet := range nvconf.PopularCapabilitySets() {
		capSets = append(capSets, capSet)
	}

	// Build all the ABIs.
	Init()
	allAbis := make(map[string]*driverABI, len(abis))
	for version, abiCons := range abis {
		allAbis[version.String()] = abiCons.cons()
	}

	// Check that the filters are correct for each capability set.
	// Dedupe the capability sets to avoid redundant tests.
	tried := make(map[nvconf.DriverCaps]struct{}, len(capSets))
	for _, caps := range capSets {
		if _, ok := tried[caps]; ok {
			continue
		}
		tried[caps] = struct{}{}
		testName := caps.String()
		if testName == "" {
			testName = "no_capabilities"
		}
		t.Run(testName, func(t *testing.T) {
			frontendIoctls := map[uint32]struct{}{}
			uvmIoctls := map[uint32]struct{}{}
			if caps != 0 {
				for frontendIoctl := range nvproxyOnlyFrontendIoctls {
					frontendIoctls[frontendIoctl] = struct{}{}
				}
				for uvmIoctl := range nvproxyOnlyUVMIoctls {
					uvmIoctls[uvmIoctl] = struct{}{}
				}
				for _, abi := range allAbis {
					for ioctl, feHandler := range abi.frontendIoctl {
						if _, nonForwarded := nonForwardedFrontendIoctls[ioctl]; nonForwarded {
							continue
						}
						if feHandler.capSet&caps != 0 {
							frontendIoctls[ioctl] = struct{}{}
						}
					}
					for ioctl, uvmHandler := range abi.uvmIoctl {
						if _, nonForwarded := nonForwardedUVMIoctls[ioctl]; nonForwarded {
							continue
						}
						if uvmHandler.capSet&caps != 0 {
							uvmIoctls[ioctl] = struct{}{}
						}
					}
				}
			}
			wantFrontendIoctls := len(frontendIoctls)
			if gotFrontendIoctls := len(frontendIoctlFilters(caps)); gotFrontendIoctls != wantFrontendIoctls {
				t.Errorf("frontendIoctlFilters(%q) returned %d frontend ioctls, expected %d", caps.String(), gotFrontendIoctls, wantFrontendIoctls)
			}
			wantUvmIoctls := len(uvmIoctls)
			if gotUvmIoctls := len(uvmIoctlFilters(caps)); gotUvmIoctls != wantUvmIoctls {
				t.Errorf("uvmIoctlFilters(%q) returned %d UVM ioctls, expected %d", caps.String(), gotUvmIoctls, wantUvmIoctls)
			}
			if t.Failed() {
				return
			}
			// Check that the total adds up too.
			ioctlRules := Filters(caps).Get(unix.SYS_IOCTL)
			if ioctlRules == nil {
				t.Fatalf("Filters(%q) returned no SYS_IOCTL rules", caps.String())
			}
			ioctlOr, isOr := ioctlRules.(seccomp.Or)
			if !isOr {
				t.Fatalf("Filters(%q) returned a non-Or rule for SYS_IOCTL: %v (type: %T)", caps.String(), ioctlRules, ioctlRules)
			}
			wantTotalIoctls := wantFrontendIoctls + wantUvmIoctls
			if gotTotalIoctls := len(ioctlOr); gotTotalIoctls != wantTotalIoctls {
				t.Errorf("Filters(%q) returned %d total ioctl rules, expected %d", caps.String(), gotTotalIoctls, wantTotalIoctls)
			}
		})
	}
}
