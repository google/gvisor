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
			params *nvgpu.NVOS54Parameters
		}
		testHandler(
			t,
			func(handler controlCmdHandler, input controlCmdInput) (uintptr, error) {
				return handler.handle(input.fi, input.params)
			},
			ctrlHandler(func(*frontendIoctlState, *nvgpu.NVOS54Parameters) (uintptr, error) {
				return 42, nil
			}, capCompute),
			controlCmdInput{fi: capComputeState},
			controlCmdInput{fi: capUtilityState},
		)
	})
	t.Run("allocation class", func(t *testing.T) {
		type allocClassInput struct {
			fi          *frontendIoctlState
			ioctlParams *nvgpu.NVOS64Parameters
			isNVOS64    bool
		}
		testHandler(
			t,
			func(handler allocationClassHandler, input allocClassInput) (uintptr, error) {
				return handler.handle(input.fi, input.ioctlParams, input.isNVOS64)
			},
			allocHandler(func(*frontendIoctlState, *nvgpu.NVOS64Parameters, bool) (uintptr, error) {
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
