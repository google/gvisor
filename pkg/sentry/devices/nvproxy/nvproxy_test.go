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
		if !abi.supported {
			continue
		}
		if abi.checksums.X86_64 == "" || abi.checksums.ARM64 == "" {
			t.Errorf("unexpected empty value for driver %q", version.String())
		}
	}
}

func TestPublicInstallerUnavailable(t *testing.T) {
	digest := strings.Repeat("a", 64)
	public := NewChecksums(digest, digest)
	noPublicAMD := public
	noPublicAMD.NoPublicX86_64Installer = true
	noPublicARM := public
	noPublicARM.NoPublicARM64Installer = true
	emptyAMD := noPublicAMD
	emptyAMD.X86_64 = ""
	emptyARM := noPublicARM
	emptyARM.ARM64 = ""
	for _, test := range []struct {
		name        string
		checksums   Checksums
		arch        string
		unavailable bool
		wantErr     bool
	}{
		{"public_amd", public, "amd64", false, false},
		{"public_arm", public, "arm64", false, false},
		{"no_driver", NewChecksums(ChecksumNoDriver, ChecksumNoDriver), "amd64", true, false},
		{"unavailable_amd", noPublicAMD, "amd64", true, false},
		{"unavailable_arm", noPublicARM, "arm64", true, false},
		{"only_amd_unavailable", noPublicAMD, "arm64", false, false},
		{"only_arm_unavailable", noPublicARM, "amd64", false, false},
		{"empty_amd", emptyAMD, "amd64", false, true},
		{"empty_arm", emptyARM, "arm64", false, true},
		{"unknown_architecture", noPublicARM, "unknown", false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			unavailable, err := test.checksums.PublicInstallerUnavailable(test.arch)
			if got, want := err != nil, test.wantErr; got != want {
				t.Fatalf("PublicInstallerUnavailable error = %v, want error %t", err, want)
			}
			if got, want := unavailable, test.unavailable; got != want {
				t.Errorf("PublicInstallerUnavailable = %t, want %t", got, want)
			}
		})
	}
}

// TestABIStructNamesInSync tests that all the supported ioctls in an ABI version are also mapped
// by GetStructNames.
func TestABIStructNamesInSync(t *testing.T) {
	Init()
	for version, abiEntry := range abis {
		t.Run(version.String(), func(t *testing.T) {
			abi := abiEntry.cons()
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
			&uvmIoctlState{nvp: capComputeNVP},
			&uvmIoctlState{nvp: capUtilityNVP},
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
	for version, abiEntry := range abis {
		allAbis[version.String()] = abiEntry.cons()
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

// TestMIGABISurface checks every registered version, including intermediate
// ABIs and newer branches that inherit an older constructor. Instance access
// must not enable the separate MIG administration interface.
func TestMIGABISurface(t *testing.T) {
	Init()
	firstGIUUID := nvconf.NewDriverVersion(550, 40, 7)
	for version, entry := range abis {
		t.Run(version.String(), func(t *testing.T) {
			abi := entry.cons()
			info := abi.getInfo()
			for _, class := range []nvgpu.ClassID{nvgpu.AMPERE_SMC_PARTITION_REF, nvgpu.AMPERE_SMC_EXEC_PARTITION_REF} {
				handler, ok := abi.allocationClass[class]
				if !ok || handler.handler == nil || handler.capSet != compUtil {
					t.Errorf("MIG reference class %s does not have a compute/utility handler", class)
				}
				if _, ok := info.AllocationInfos[class]; !ok {
					t.Errorf("MIG reference class %s has no driver parity metadata", class)
				}
			}
			for _, command := range []uint32{
				nvgpu.NV0000_CTRL_CMD_CLIENT_GET_HANDLE_INFO,
				nvgpu.NV2080_CTRL_CMD_GPU_GET_PARTITIONS,
				nvgpu.NV2080_CTRL_CMD_GPU_GET_COMPUTE_PROFILES,
				nvgpu.NVC637_CTRL_CMD_EXEC_PARTITIONS_GET,
				nvgpu.NVC637_CTRL_EXEC_PARTITIONS_GET_ACTIVE_IDS,
				nvgpu.NVC637_CTRL_CMD_GET_UUID,
				nvgpu.NVC638_CTRL_CMD_GET_UUID,
			} {
				wantPresent := command != nvgpu.NVC637_CTRL_CMD_GET_UUID || version.IsGreaterThan(firstGIUUID)
				handler, present := abi.controlCmd[command]
				if present != wantPresent {
					t.Errorf("MIG query %#x present=%t, want %t", command, present, wantPresent)
				}
				_, haveMetadata := info.ControlInfos[command]
				if haveMetadata != wantPresent {
					t.Errorf("MIG query %#x parity metadata present=%t, want %t", command, haveMetadata, wantPresent)
				}
				if present && (handler.handler == nil || handler.capSet != compUtil) {
					t.Errorf("MIG query %#x does not have a compute/utility handler", command)
				}
			}
			for _, command := range []uint32{
				0x20800174, // NV2080_CTRL_CMD_GPU_SET_PARTITIONS
				0x20800176, // NV2080_CTRL_CMD_GPU_CONFIGURE_PARTITION
				0xc6370101, // NVC637_CTRL_CMD_EXEC_PARTITIONS_CREATE
				0xc6370102, // NVC637_CTRL_CMD_EXEC_PARTITIONS_DELETE
			} {
				if _, ok := abi.controlCmd[command]; ok {
					t.Errorf("MIG administration command %#x is allowlisted", command)
				}
				if _, ok := info.ControlInfos[command]; ok {
					t.Errorf("MIG administration command %#x has allowlist metadata", command)
				}
			}
			const smcConfigSession nvgpu.ClassID = 0xc639 // AMPERE_SMC_CONFIG_SESSION
			if _, ok := abi.allocationClass[smcConfigSession]; ok {
				t.Errorf("MIG configuration session class %s is allowlisted", smcConfigSession)
			}
		})
	}
}

// TestUnknownDriverRejected verifies that the opt-in for known intermediate
// ABIs cannot select a guessed ABI for a driver absent from the registry.
func TestUnknownDriverRejected(t *testing.T) {
	Init()
	version := nvconf.NewDriverVersion(99999, 1, 1)
	if _, ok := abis[version]; ok {
		t.Fatalf("test driver %s is registered", version)
	}
	for _, allowUnsupported := range []bool{false, true} {
		_, err := Register(nil, &Options{DriverVersion: version, AllowUnsupportedDriver: allowUnsupported})
		if err == nil || !strings.Contains(err.Error(), "unsupported Nvidia driver version") {
			t.Errorf("Register unknown version, AllowUnsupportedDriver=%t: got %v", allowUnsupported, err)
		}
	}
}
