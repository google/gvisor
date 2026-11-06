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
	"sync"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/abi/nvgpu"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/devices/nvproxy/nvconf"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/testutil"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/limits"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
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

const fakeHostFD = 0x7eadbeef

var (
	installFakeHostFDOnce sync.Once
	installFakeHostFDErr  error
)

func installFakeHostIoctlFilter(t *testing.T) {
	t.Helper()
	installFakeHostFDOnce.Do(func() {
		prog := &seccomp.Program{
			RuleSets: []seccomp.RuleSet{
				{
					Rules: seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
						unix.SYS_IOCTL: seccomp.PerArg{
							seccomp.EqualTo(fakeHostFD),
						},
					}),
					Action: seccomp.ReturnError.Code(0),
				},
			},
			Options: seccomp.ProgramOptions{
				DefaultAction: seccomp.Allow,
				BadArchAction: seccomp.Allow,
			},
		}
		instrs, _, err := prog.Build()
		if err != nil {
			installFakeHostFDErr = err
			return
		}
		installFakeHostFDErr = seccomp.SetFilter(instrs)
	})
	if installFakeHostFDErr != nil {
		t.Fatalf("failed to install fake host ioctl seccomp filter: %v", installFakeHostFDErr)
	}
}

func TestDebugAndEventIoctls(t *testing.T) {
	installFakeHostIoctlFilter(t)

	k, err := testutil.Boot()
	if err != nil {
		t.Fatalf("testutil.Boot: %v", err)
	}
	ctx := k.SupervisorContext()
	creds := auth.CredentialsFromContext(ctx)
	mntns, err := k.VFS().NewMountNamespace(ctx, creds, "", "tmpfs", &vfs.MountOptions{}, nil)
	if err != nil {
		t.Fatalf("NewMountNamespace: %v", err)
	}
	defer mntns.DecRef(ctx)
	root := mntns.Root(ctx)
	defer root.DecRef(ctx)
	task, err := testutil.CreateTask(ctx, "nvproxy-test", k.GlobalInit(), mntns, root, root)
	if err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	if _, err := task.MemoryManager().SetMmapLayout(arch.New(arch.AMD64), limits.FromContext(ctx)); err != nil {
		t.Fatalf("SetMmapLayout: %v", err)
	}

	mappedAddr, err := task.MemoryManager().MMap(ctx, memmap.MMapOpts{
		Length:   4 * hostarch.PageSize,
		Private:  true,
		Perms:    hostarch.ReadWrite,
		MaxPerms: hostarch.AnyAccess,
	})
	if err != nil {
		t.Fatalf("MMap: %v", err)
	}
	if _, err := task.MemoryManager().CopyOut(ctx, mappedAddr, make([]byte, 4*hostarch.PageSize), usermem.IOOpts{}); err != nil {
		t.Fatalf("CopyOut init: %v", err)
	}
	paramAddr := mappedAddr
	auxAddr := mappedAddr + hostarch.PageSize
	osDescAddr := mappedAddr + 2*hostarch.PageSize
	roAddr := mappedAddr + 3*hostarch.PageSize

	// Populate roAddr before making it read-only so CopyIn succeeds and CopyOut fails.
	roEventParams := nvgpu.NVOS41_PARAMETERS{PEvent: nvgpu.P64(uint64(auxAddr))}
	if _, err := roEventParams.CopyOut(task, roAddr); err != nil {
		t.Fatalf("CopyOut roAddr: %v", err)
	}
	roWriteParams := nvgpu.NV83DE_CTRL_DEBUG_WRITE_MEMORY_PARAMS{
		HMemory: 0x101,
		Length:  16,
		Buffer:  nvgpu.P64(uint64(osDescAddr)),
	}
	if _, err := roWriteParams.CopyOut(task, roAddr+128); err != nil {
		t.Fatalf("CopyOut roAddr+128: %v", err)
	}
	if err := task.MemoryManager().MProtect(roAddr, hostarch.PageSize, hostarch.Read, false); err != nil {
		t.Fatalf("MProtect: %v", err)
	}
	if _, err := task.MemoryManager().CopyIn(ctx, roAddr, make([]byte, hostarch.PageSize), usermem.IOOpts{}); err != nil {
		t.Fatalf("CopyIn roAddr init: %v", err)
	}

	clientH := nvgpu.Handle{Val: 0x10}
	client := &rootClient{
		resources: make(map[nvgpu.Handle]*object),
	}
	client.handle = clientH
	nvp := &nvproxy{
		clients: map[nvgpu.Handle]*rootClient{
			clientH: client,
		},
		frontendFDs: make(map[*frontendFD]struct{}),
	}
	client.objsMu.Lock()
	nvp.objAdd(ctx, client, clientH, nvgpu.NV01_ROOT_CLIENT, client, nvgpu.Handle{})
	client.objsMu.Unlock()

	dev := &frontendDevice{nvp: nvp}
	feFD := &frontendFD{
		dev:    dev,
		hostFD: fakeHostFD,
	}

	t.Run("nvgpu_helpers", func(t *testing.T) {
		memAllocParams := nvgpu.NV_MEMORY_ALLOCATION_PARAMS{Attr2: 0x1234}
		if got := memAllocParams.GetAttr2(); got != 0x1234 {
			t.Errorf("GetAttr2() = %#x, want 0x1234", got)
		}
		var nvos41 nvgpu.NVOS41_PARAMETERS
		nvos41.SetStatus(nvgpu.NV_ERR_INVALID_ADDRESS)
		if got := nvos41.GetStatus(); got != nvgpu.NV_ERR_INVALID_ADDRESS {
			t.Errorf("GetStatus() = %#x, want %#x", got, nvgpu.NV_ERR_INVALID_ADDRESS)
		}
	})

	t.Run("rmGetEventData", func(t *testing.T) {
		fi := &frontendIoctlState{
			fd:              feFD,
			ctx:             ctx,
			t:               task,
			nr:              nvgpu.NV_ESC_RM_GET_EVENT_DATA,
			ioctlParamsAddr: paramAddr,
			ioctlParamsSize: nvgpu.SizeofNVOS41Parameters - 1,
		}
		if _, err := rmGetEventData(fi); err != linuxerr.EINVAL {
			t.Errorf("rmGetEventData size mismatch err = %v, want EINVAL", err)
		}

		fi.ioctlParamsSize = nvgpu.SizeofNVOS41Parameters
		fi.ioctlParamsAddr = 0
		if _, err := rmGetEventData(fi); err == nil {
			t.Errorf("rmGetEventData bad ioctlParamsAddr err = nil, want non-nil")
		}
		fi.ioctlParamsAddr = paramAddr

		badParams := nvgpu.NVOS41_PARAMETERS{PEvent: 0}
		if _, err := badParams.CopyOut(task, paramAddr); err != nil {
			t.Fatalf("CopyOut: %v", err)
		}
		if _, err := rmGetEventData(fi); err != nil {
			t.Fatalf("rmGetEventData bad PEvent err = %v, want nil", err)
		}
		var outParams nvgpu.NVOS41_PARAMETERS
		if _, err := outParams.CopyIn(task, paramAddr); err != nil {
			t.Fatalf("CopyIn: %v", err)
		}
		if outParams.GetStatus() != nvgpu.NV_ERR_INVALID_ADDRESS {
			t.Errorf("rmGetEventData bad PEvent status = %#x, want %#x", outParams.GetStatus(), nvgpu.NV_ERR_INVALID_ADDRESS)
		}

		roPEventParams := nvgpu.NVOS41_PARAMETERS{PEvent: nvgpu.P64(uint64(roAddr))}
		if _, err := roPEventParams.CopyOut(task, paramAddr); err != nil {
			t.Fatalf("CopyOut: %v", err)
		}
		if _, err := rmGetEventData(fi); err != nil {
			t.Fatalf("rmGetEventData read-only PEvent err = %v, want nil", err)
		}
		if _, err := outParams.CopyIn(task, paramAddr); err != nil {
			t.Fatalf("CopyIn: %v", err)
		}
		if outParams.GetStatus() != nvgpu.NV_ERR_INVALID_ADDRESS {
			t.Errorf("rmGetEventData read-only PEvent status = %#x, want %#x", outParams.GetStatus(), nvgpu.NV_ERR_INVALID_ADDRESS)
		}

		fi.ioctlParamsAddr = roAddr
		if _, err := rmGetEventData(fi); err == nil {
			t.Errorf("rmGetEventData read-only ioctlParamsAddr err = nil, want non-nil")
		}
		fi.ioctlParamsAddr = paramAddr

		goodParams := nvgpu.NVOS41_PARAMETERS{PEvent: nvgpu.P64(uint64(auxAddr))}
		if _, err := goodParams.CopyOut(task, paramAddr); err != nil {
			t.Fatalf("CopyOut: %v", err)
		}
		feFD.hostFD = -1
		if _, err := rmGetEventData(fi); err != unix.EBADF {
			t.Errorf("rmGetEventData EBADF err = %v, want EBADF", err)
		}
		feFD.hostFD = fakeHostFD
		if _, err := rmGetEventData(fi); err != nil {
			t.Fatalf("rmGetEventData success err = %v, want nil", err)
		}
	})

	t.Run("alloc_and_debug_memory", func(t *testing.T) {
		fi := &frontendIoctlState{
			fd:              feFD,
			ctx:             ctx,
			t:               task,
			ioctlParamsAddr: paramAddr,
		}

		// 1. rmAllocMemoryParams with read-write and read-only Attr2.
		rwObjH := nvgpu.Handle{Val: 0x101}
		roObjH := nvgpu.Handle{Val: 0x102}
		for _, tc := range []struct {
			handle       nvgpu.Handle
			attr2        uint32
			wantWritable bool
		}{
			{
				handle:       rwObjH,
				attr2:        nvgpu.NVOS32_ATTR2_PROTECTION_USER_READ_WRITE << nvgpu.NVOS32_ATTR2_PROTECTION_USER_SHIFT,
				wantWritable: true,
			},
			{
				handle:       roObjH,
				attr2:        nvgpu.NVOS32_ATTR2_PROTECTION_USER_MASK << nvgpu.NVOS32_ATTR2_PROTECTION_USER_SHIFT,
				wantWritable: false,
			},
		} {
			allocParams := nvgpu.NV_MEMORY_ALLOCATION_PARAMS{Attr2: tc.attr2}
			if _, err := allocParams.CopyOut(task, auxAddr); err != nil {
				t.Fatalf("CopyOut: %v", err)
			}
			ioctlParams := nvgpu.NVOS64_PARAMETERS{
				HRoot:         clientH,
				HObjectParent: clientH,
				HObjectNew:    tc.handle,
				HClass:        nvgpu.NV01_MEMORY_LOCAL_USER,
				PAllocParms:   nvgpu.P64(uint64(auxAddr)),
			}
			if _, err := rmAllocMemoryParams[nvgpu.NV_MEMORY_ALLOCATION_PARAMS](fi, &ioctlParams, true); err != nil {
				t.Fatalf("rmAllocMemoryParams(%v) err = %v", tc.handle, err)
			}
			client.objsMu.Lock()
			obj := client.getObject(ctx, tc.handle)
			client.objsMu.Unlock()
			if obj == nil || obj.debugWritable != tc.wantWritable {
				t.Errorf("obj(%v).debugWritable = %v, want %v", tc.handle, obj != nil && obj.debugWritable, tc.wantWritable)
			}
		}

		// 2. rmAllocMemorySimple & rmAllocMemorySystem.
		vd := k.VFS().NewAnonVirtualDentry("nvproxy")
		defer vd.DecRef(ctx)
		mapFDImpl := &frontendFD{
			dev:    dev,
			hostFD: -1,
		}
		if err := mapFDImpl.vfsfd.Init(mapFDImpl, linux.O_RDWR, creds, vd.Mount(), vd.Dentry(), &vfs.FileDescriptionOptions{SpecialFile: true}); err != nil {
			t.Fatalf("vfsfd.Init: %v", err)
		}
		mapFDImpl.vfsfd.IncRef()
		mapFDNum, err := task.FDTable().NewFD(ctx, 0, &mapFDImpl.vfsfd, kernel.FDFlags{})
		if err != nil {
			t.Fatalf("NewFD: %v", err)
		}

		sysRWHandle := nvgpu.Handle{Val: 0x103}
		sysROHandle := nvgpu.Handle{Val: 0x104}
		nvos02RW := nvgpu.IoctlNVOS02ParametersWithFD{
			Params: nvgpu.NVOS02_PARAMETERS{
				HRoot:         clientH,
				HObjectParent: clientH,
				HObjectNew:    sysRWHandle,
				HClass:        nvgpu.NV01_MEMORY_SYSTEM,
				Flags:         nvgpu.NVOS02_FLAGS_ALLOC_NONE << nvgpu.NVOS02_FLAGS_ALLOC_SHIFT,
			},
			FD: mapFDNum,
		}
		if _, err := rmAllocMemorySystem(fi, &nvos02RW); err != nil {
			t.Fatalf("rmAllocMemorySystem err = %v", err)
		}
		nvos02RO := nvgpu.IoctlNVOS02ParametersWithFD{
			Params: nvgpu.NVOS02_PARAMETERS{
				HRoot:         clientH,
				HObjectParent: clientH,
				HObjectNew:    sysROHandle,
				HClass:        nvgpu.NV01_MEMORY_LOCAL_USER,
				Flags:         nvgpu.NVOS02_FLAGS_ALLOC_USER_READ_ONLY_YES << nvgpu.NVOS02_FLAGS_ALLOC_USER_READ_ONLY_SHIFT,
			},
		}
		if _, err := rmAllocMemorySimple(fi, &nvos02RO); err != nil {
			t.Fatalf("rmAllocMemorySimple err = %v", err)
		}

		// 3. rmAllocOSDescriptor & rmVidHeapControlAllocOSDescriptor & rmVidHeapControlAllocSize.
		osDescRWHandle := nvgpu.Handle{Val: 0x105}
		osDescROHandle := nvgpu.Handle{Val: 0x106}
		for _, tc := range []struct {
			handle       nvgpu.Handle
			flags        uint32
			wantWritable bool
		}{
			{osDescRWHandle, 0, true},
			{osDescROHandle, nvgpu.NVOS02_FLAGS_ALLOC_USER_READ_ONLY_YES << nvgpu.NVOS02_FLAGS_ALLOC_USER_READ_ONLY_SHIFT, false},
		} {
			osDescParams := nvgpu.IoctlNVOS02ParametersWithFD{
				Params: nvgpu.NVOS02_PARAMETERS{
					HRoot:         clientH,
					HObjectParent: clientH,
					HObjectNew:    tc.handle,
					HClass:        nvgpu.NV01_MEMORY_SYSTEM_OS_DESCRIPTOR,
					Flags:         tc.flags,
					PMemory:       nvgpu.P64(uint64(osDescAddr)),
					Limit:         hostarch.PageSize - 1,
				},
			}
			if _, err := rmAllocOSDescriptor(fi, &osDescParams); err != nil {
				t.Fatalf("rmAllocOSDescriptor(%v) err = %v", tc.handle, err)
			}
			client.objsMu.Lock()
			obj := client.getObject(ctx, tc.handle)
			gotWritable := obj != nil && obj.debugWritable
			releases := nvp.objFree(ctx, client, tc.handle)
			client.objsMu.Unlock()
			for _, r := range releases {
				r()
			}
			if gotWritable != tc.wantWritable {
				t.Errorf("osDesc(%v).debugWritable = %v, want %v", tc.handle, gotWritable, tc.wantWritable)
			}
		}

		var heapOSDescIoctl nvgpu.NVOS32_PARAMETERS
		heapOSDescIoctl.HRoot = clientH
		heapOSDescIoctl.HObjectParent = clientH
		heapOSDescHMemory := nvgpu.Handle{Val: 0x107}
		hostarch.ByteOrder.PutUint32(heapOSDescIoctl.Data[0:4], heapOSDescHMemory.Val)
		hostarch.ByteOrder.PutUint32(heapOSDescIoctl.Data[8:12], nvgpu.NVOS32_ALLOC_FLAGS_USER_READ_ONLY)
		hostarch.ByteOrder.PutUint32(heapOSDescIoctl.Data[16:20], nvgpu.NVOS32_ATTR2_PROTECTION_USER_READ_WRITE<<nvgpu.NVOS32_ATTR2_PROTECTION_USER_SHIFT)
		hostarch.ByteOrder.PutUint64(heapOSDescIoctl.Data[24:32], uint64(osDescAddr))
		hostarch.ByteOrder.PutUint64(heapOSDescIoctl.Data[32:40], hostarch.PageSize-1)
		if _, err := rmVidHeapControlAllocOSDescriptor(fi, &heapOSDescIoctl); err != nil {
			t.Fatalf("rmVidHeapControlAllocOSDescriptor err = %v", err)
		}
		client.objsMu.Lock()
		heapOSObj := client.getObject(ctx, heapOSDescHMemory)
		if heapOSObj == nil || heapOSObj.debugWritable {
			t.Errorf("heapOSObj.debugWritable = %v, want false", heapOSObj != nil && heapOSObj.debugWritable)
		}
		releases := nvp.objFree(ctx, client, heapOSDescHMemory)
		client.objsMu.Unlock()
		for _, r := range releases {
			r()
		}

		for _, tc := range []struct {
			handle       nvgpu.Handle
			flags        uint32
			wantWritable bool
		}{
			{nvgpu.Handle{Val: 0x108}, nvgpu.NVOS32_ALLOC_FLAGS_VIRTUAL, false},
			{nvgpu.Handle{Val: 0x109}, 0, true},
		} {
			var heapSizeIoctl nvgpu.NVOS32_PARAMETERS
			heapSizeIoctl.HRoot = clientH
			heapSizeIoctl.HObjectParent = clientH
			hostarch.ByteOrder.PutUint32(heapSizeIoctl.Data[4:8], tc.handle.Val)
			hostarch.ByteOrder.PutUint32(heapSizeIoctl.Data[12:16], tc.flags)
			hostarch.ByteOrder.PutUint32(heapSizeIoctl.Data[80:84], nvgpu.NVOS32_ATTR2_PROTECTION_USER_READ_WRITE<<nvgpu.NVOS32_ATTR2_PROTECTION_USER_SHIFT)
			if _, err := rmVidHeapControlAllocSize(fi, &heapSizeIoctl); err != nil {
				t.Fatalf("rmVidHeapControlAllocSize(%v) err = %v", tc.handle, err)
			}
			client.objsMu.Lock()
			obj := client.getObject(ctx, tc.handle)
			client.objsMu.Unlock()
			if obj == nil || obj.debugWritable != tc.wantWritable {
				t.Errorf("heapSize(%v).debugWritable = %v, want %v", tc.handle, obj != nil && obj.debugWritable, tc.wantWritable)
			}
		}

		// 4. objDup preserves debugWritable.
		dupRWH := nvgpu.Handle{Val: 0x201}
		dupROH := nvgpu.Handle{Val: 0x202}
		client.objsMu.Lock()
		nvp.objDup(ctx, client, client, dupRWH, clientH, rwObjH)
		nvp.objDup(ctx, client, client, dupROH, clientH, roObjH)
		dupRWObj := client.getObject(ctx, dupRWH)
		dupROObj := client.getObject(ctx, dupROH)
		client.objsMu.Unlock()
		if dupRWObj == nil || !dupRWObj.debugWritable {
			t.Errorf("dupRWObj.debugWritable = %v, want true", dupRWObj != nil && dupRWObj.debugWritable)
		}
		if dupROObj == nil || dupROObj.debugWritable {
			t.Errorf("dupROObj.debugWritable = %v, want false", dupROObj != nil && dupROObj.debugWritable)
		}

		// 5. ctrlDebugReadMemory & ctrlDebugWriteMemory.
		readParams := nvgpu.NV83DE_CTRL_DEBUG_READ_MEMORY_PARAMS{
			Length: debugMemoryMaxLength + 1,
		}
		if _, err := readParams.CopyOut(task, auxAddr); err != nil {
			t.Fatalf("CopyOut: %v", err)
		}
		readIoctl := nvgpu.NVOS54_PARAMETERS{
			HClient:    clientH,
			Params:     nvgpu.P64(uint64(auxAddr)),
			ParamsSize: uint32(readParams.SizeBytes()),
		}
		if _, err := ctrlDebugReadMemory(fi, &readIoctl); err != nil {
			t.Fatalf("ctrlDebugReadMemory over-limit err = %v", err)
		}
		if readIoctl.Status != nvgpu.NV_ERR_INVALID_ARGUMENT {
			t.Errorf("ctrlDebugReadMemory over-limit status = %#x, want %#x", readIoctl.Status, nvgpu.NV_ERR_INVALID_ARGUMENT)
		}

		var writeParams nvgpu.NV83DE_CTRL_DEBUG_WRITE_MEMORY_PARAMS
		badSizeIoctl := nvgpu.NVOS54_PARAMETERS{ParamsSize: uint32(writeParams.SizeBytes() - 1)}
		if _, err := ctrlDebugWriteMemory(fi, &badSizeIoctl); err != linuxerr.EINVAL {
			t.Errorf("ctrlDebugWriteMemory size mismatch err = %v, want EINVAL", err)
		}
		badAddrIoctl := nvgpu.NVOS54_PARAMETERS{
			Params:     0,
			ParamsSize: uint32(writeParams.SizeBytes()),
		}
		if _, err := ctrlDebugWriteMemory(fi, &badAddrIoctl); err == nil {
			t.Errorf("ctrlDebugWriteMemory bad Params addr err = nil, want non-nil")
		}
		badBufParams := nvgpu.NV83DE_CTRL_DEBUG_WRITE_MEMORY_PARAMS{
			HMemory: rwObjH.Val,
			Length:  16,
			Buffer:  1,
		}
		if _, err := badBufParams.CopyOut(task, auxAddr); err != nil {
			t.Fatalf("CopyOut: %v", err)
		}
		badBufIoctl := nvgpu.NVOS54_PARAMETERS{
			HClient:    clientH,
			Params:     nvgpu.P64(uint64(auxAddr)),
			ParamsSize: uint32(badBufParams.SizeBytes()),
		}
		if _, err := ctrlDebugWriteMemory(fi, &badBufIoctl); err == nil {
			t.Errorf("ctrlDebugWriteMemory bad Buffer addr err = nil, want non-nil")
		}

		roParamsIoctl := nvgpu.NVOS54_PARAMETERS{
			HClient:    clientH,
			Params:     nvgpu.P64(uint64(roAddr + 128)),
			ParamsSize: uint32(writeParams.SizeBytes()),
		}
		feFD.hostFD = -1
		if _, err := ctrlDebugWriteMemory(fi, &roParamsIoctl); err != unix.EBADF {
			t.Errorf("ctrlDebugWriteMemory EBADF err = %v, want EBADF", err)
		}
		feFD.hostFD = fakeHostFD
		if _, err := ctrlDebugWriteMemory(fi, &roParamsIoctl); err == nil {
			t.Errorf("ctrlDebugWriteMemory read-only Params addr err = nil, want non-nil")
		}

		for _, tc := range []struct {
			name       string
			hClient    nvgpu.Handle
			params     nvgpu.NV83DE_CTRL_DEBUG_WRITE_MEMORY_PARAMS
			wantStatus uint32
		}{
			{
				name:    "length_exceeds_max",
				hClient: clientH,
				params: nvgpu.NV83DE_CTRL_DEBUG_WRITE_MEMORY_PARAMS{
					Length: debugMemoryMaxLength + 1,
				},
				wantStatus: nvgpu.NV_ERR_INVALID_ARGUMENT,
			},
			{
				name:    "unknown_client",
				hClient: nvgpu.Handle{Val: 0x9999},
				params: nvgpu.NV83DE_CTRL_DEBUG_WRITE_MEMORY_PARAMS{
					HMemory: rwObjH.Val,
				},
				wantStatus: nvgpu.NV_ERR_INVALID_CLIENT,
			},
			{
				name:    "unknown_memory_object",
				hClient: clientH,
				params: nvgpu.NV83DE_CTRL_DEBUG_WRITE_MEMORY_PARAMS{
					HMemory: 0x9999,
				},
				wantStatus: nvgpu.NV_ERR_INVALID_OBJECT_HANDLE,
			},
			{
				name:    "read_only_memory_object",
				hClient: clientH,
				params: nvgpu.NV83DE_CTRL_DEBUG_WRITE_MEMORY_PARAMS{
					HMemory: roObjH.Val,
				},
				wantStatus: nvgpu.NV_ERR_INSUFFICIENT_PERMISSIONS,
			},
			{
				name:    "writable_memory_object_ok",
				hClient: clientH,
				params: nvgpu.NV83DE_CTRL_DEBUG_WRITE_MEMORY_PARAMS{
					HMemory: rwObjH.Val,
					Length:  16,
					Buffer:  nvgpu.P64(uint64(osDescAddr)),
				},
				wantStatus: nvgpu.NV_OK,
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if _, err := tc.params.CopyOut(task, auxAddr); err != nil {
					t.Fatalf("CopyOut: %v", err)
				}
				ioctlParams := nvgpu.NVOS54_PARAMETERS{
					HClient:    tc.hClient,
					Params:     nvgpu.P64(uint64(auxAddr)),
					ParamsSize: uint32(tc.params.SizeBytes()),
				}
				if _, err := ctrlDebugWriteMemory(fi, &ioctlParams); err != nil {
					t.Fatalf("ctrlDebugWriteMemory err = %v", err)
				}
				if ioctlParams.Status != tc.wantStatus {
					t.Errorf("ctrlDebugWriteMemory status = %#x, want %#x", ioctlParams.Status, tc.wantStatus)
				}
			})
		}
	})
}
