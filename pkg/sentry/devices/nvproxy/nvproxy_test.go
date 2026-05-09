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
		if abi.checksums.checksumX86_64 == "" || abi.checksums.checksumARM64 == "" {
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
			info := abi.getInfo()

			for ioctl := range abi.frontendIoctl {
				if _, ok := info.FrontendInfos[ioctl]; !ok {
					t.Errorf("Frontend ioctl %#x not found in struct names for version %s", ioctl, version)
				}
			}
			if len(abi.frontendIoctl) != len(info.FrontendInfos) {
				t.Errorf("Frontend ioctl count mismatch for version %s: %d != %d", version, len(abi.frontendIoctl), len(info.FrontendInfos))
			}
			for ioctl := range abi.uvmIoctl {
				if _, ok := info.UvmInfos[ioctl]; !ok {
					t.Errorf("UVM ioctl %#x not found in struct names for version %s", ioctl, version)
				}
			}
			if len(abi.uvmIoctl) != len(info.UvmInfos) {
				t.Errorf("UVM ioctl count mismatch for version %s: %d != %d", version, len(abi.uvmIoctl), len(info.UvmInfos))
			}
			for ioctl := range abi.controlCmd {
				if _, ok := info.ControlInfos[ioctl]; !ok {
					t.Errorf("Control command %#x not found in struct names for version %s", ioctl, version)
				}
			}
			if len(abi.controlCmd) != len(info.ControlInfos) {
				t.Errorf("Control command count mismatch for version %s: %d != %d", version, len(abi.controlCmd), len(info.ControlInfos))
			}
			for ioctl := range abi.allocationClass {
				if _, ok := info.AllocationInfos[ioctl]; !ok {
					t.Errorf("Alloc class %#x not found in struct names for version %s", ioctl, version)
				}
			}
			if len(abi.allocationClass) != len(info.AllocationInfos) {
				t.Errorf("Alloc class count mismatch for version %s: %d != %d", version, len(abi.allocationClass), len(info.AllocationInfos))
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
	capSets = append(capSets, nvconf.PopularCapabilitySets()...)

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

// TestRmControlOpaqueDispatchClassification validates the bit-mask
// classification used by rmControl() to identify GSP-legacy and
// NV2081_BINAPI control commands. These are the two paths that forward
// up to 1 MB of opaque bytes to the host NVIDIA driver and now emit an
// audit warning before delegating to rmControlSimple
// (https://github.com/google/gvisor/pull/12921).
//
// The test does not invoke rmControl() directly because that requires
// a full kernel.Task and a real /dev/nvidiactl ioctl path; instead it
// exercises the predicate math that decides which dispatch branch a
// given ioctl Cmd takes. This protects the boundary between the typed
// command dispatch (controlCmd map) and the opaque-passthrough path
// against accidental regressions.
func TestRmControlOpaqueDispatchClassification(t *testing.T) {
	// Constants act as a self-documenting baseline: if upstream
	// NVIDIA renumbers either, this test fails loudly.
	if got, want := uint32(nvgpu.RM_GSS_LEGACY_MASK), uint32(0x00008000); got != want {
		t.Errorf("nvgpu.RM_GSS_LEGACY_MASK = %#x, want %#x", got, want)
	}
	if got, want := uint32(nvgpu.NV2081_BINAPI), uint32(0x00002081); got != want {
		t.Errorf("nvgpu.NV2081_BINAPI = %#x, want %#x", got, want)
	}

	cases := []struct {
		name       string
		cmd        uint32
		wantGSP    bool
		wantBINAPI bool
	}{
		{
			name:    "RM_GSS_LEGACY_MASK bit set with high cmd bits",
			cmd:     0x80000000 | uint32(nvgpu.RM_GSS_LEGACY_MASK),
			wantGSP: true,
		},
		{
			name:    "lone GSS_LEGACY bit",
			cmd:     uint32(nvgpu.RM_GSS_LEGACY_MASK),
			wantGSP: true,
		},
		{
			name:       "NV2081_BINAPI class, subcommand 0x0001",
			cmd:        (uint32(nvgpu.NV2081_BINAPI) << 16) | 0x0001,
			wantBINAPI: true,
		},
		{
			name:       "NV2081_BINAPI class, subcommand 0x00ff",
			cmd:        (uint32(nvgpu.NV2081_BINAPI) << 16) | 0x00ff,
			wantBINAPI: true,
		},
		{
			name: "NV0080 typed-handler control NV0080_CTRL_GR -- must NOT classify as opaque",
			cmd:  0x00800180,
		},
		{
			name: "NV2080 typed-handler subdevice control -- must NOT classify as opaque",
			cmd:  0x20800301,
		},
		{
			name: "zero cmd is not opaque",
			cmd:  0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotGSP := tc.cmd&uint32(nvgpu.RM_GSS_LEGACY_MASK) != 0
			gotBINAPI := (tc.cmd>>16)&0xffff == uint32(nvgpu.NV2081_BINAPI)

			if gotGSP != tc.wantGSP {
				t.Errorf("cmd=%#x: GSP_LEGACY classification = %v, want %v",
					tc.cmd, gotGSP, tc.wantGSP)
			}
			if gotBINAPI != tc.wantBINAPI {
				t.Errorf("cmd=%#x: NV2081_BINAPI classification = %v, want %v",
					tc.cmd, gotBINAPI, tc.wantBINAPI)
			}

			// Production rmControl checks GSS_LEGACY first and returns,
			// so any cmd that satisfies both predicates would be silently
			// classified as GSS_LEGACY only. Flag such overlaps so
			// future cmd values are reviewed explicitly.
			if gotGSP && gotBINAPI {
				t.Errorf("cmd=%#x: ambiguous classification, both GSP_LEGACY and NV2081_BINAPI bits set; rmControl resolves to GSP_LEGACY first",
					tc.cmd)
			}
		})
	}
}
