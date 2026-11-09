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

package nvproxy

import (
	"bytes"
	"testing"
	"unsafe"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/abi/nvgpu"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/testutil"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/tmpfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// testFiller is the byte that newTestIoctl fills the application page with.
const testFiller = 0xa5

// newTestIoctl returns the state of a frontend ioctl made by a task of a test
// kernel, whose parameters are at the start of a page of the task's memory
// filled with testFiller, on an nvproxy that has no clients.
func newTestIoctl(t *testing.T) *frontendIoctlState {
	t.Helper()
	k, err := testutil.Boot()
	if err != nil {
		t.Fatalf("Boot failed: %v", err)
	}
	ctx := k.SupervisorContext()
	creds := auth.CredentialsFromContext(ctx)
	mntns, err := k.VFS().NewMountNamespace(ctx, creds, "", tmpfs.Name, &vfs.MountOptions{}, k)
	if err != nil {
		t.Fatalf("NewMountNamespace failed: %v", err)
	}
	t.Cleanup(func() { mntns.DecRef(ctx) })
	root := mntns.Root(ctx)
	t.Cleanup(func() { root.DecRef(ctx) })
	tg := k.NewThreadGroup(k.RootPIDNamespace(), kernel.NewSignalHandlers(), linux.SIGCHLD, k.GlobalInit().Limits())
	task, err := testutil.CreateTask(ctx, "nvproxy", tg, mntns, root, root)
	if err != nil {
		t.Fatalf("CreateTask failed: %v", err)
	}
	if _, err := task.MemoryManager().SetMmapLayout(task.Arch(), tg.Limits()); err != nil {
		t.Fatalf("SetMmapLayout failed: %v", err)
	}
	page, err := task.MemoryManager().MMap(ctx, memmap.MMapOpts{
		Length:   hostarch.PageSize,
		Private:  true,
		Perms:    hostarch.ReadWrite,
		MaxPerms: hostarch.AnyAccess,
	})
	if err != nil {
		t.Fatalf("MMap failed: %v", err)
	}
	if _, err := task.CopyOutBytes(page, bytes.Repeat([]byte{testFiller}, hostarch.PageSize)); err != nil {
		t.Fatalf("CopyOutBytes failed: %v", err)
	}
	return &frontendIoctlState{
		fd:              &frontendFD{dev: &frontendDevice{nvp: &nvproxy{}}},
		ctx:             task,
		t:               task,
		ioctlParamsAddr: page,
	}
}

// TestAllocTiledPitchHeightInvalidClientCopiesOutApplicationAddress checks
// that NVOS32_FUNCTION_ALLOC_TILED_PITCH_HEIGHT with an unknown client copies
// out the application's Address with NV_ERR_INVALID_CLIENT, not the sentry
// address that stands in for it while the ioctl runs.
func TestAllocTiledPitchHeightInvalidClientCopiesOutApplicationAddress(t *testing.T) {
	fi := newTestIoctl(t)
	var params nvgpu.NVOS32_PARAMETERS
	fi.nr = nvgpu.NV_ESC_RM_VID_HEAP_CONTROL
	fi.ioctlParamsSize = uint32(params.SizeBytes())
	params.HRoot = nvgpu.Handle{Val: 0xc1d00001}
	params.Function = nvgpu.NVOS32_FUNCTION_ALLOC_TILED_PITCH_HEIGHT
	// The address that the parameters point to follows them in the page.
	appAddress := nvgpu.P64(uint64(fi.ioctlParamsAddr) + uint64(params.SizeBytes()))
	(*nvgpu.NVOS32AllocTiledPitchHeight)(unsafe.Pointer(&params.Data)).Address = appAddress
	if _, err := rmVidHeapControlAllocTiledPitchHeight(fi, &params); err != nil {
		t.Fatalf("rmVidHeapControlAllocTiledPitchHeight failed: %v", err)
	}

	var got nvgpu.NVOS32_PARAMETERS
	if _, err := got.CopyIn(fi.t, fi.ioctlParamsAddr); err != nil {
		t.Fatalf("CopyIn failed: %v", err)
	}
	if got.Status != nvgpu.NV_ERR_INVALID_CLIENT {
		t.Errorf("Status = %#x, want NV_ERR_INVALID_CLIENT (%#x)", got.Status, nvgpu.NV_ERR_INVALID_CLIENT)
	}
	if gotAddress := (*nvgpu.NVOS32AllocTiledPitchHeight)(unsafe.Pointer(&got.Data)).Address; gotAddress != appAddress {
		t.Errorf("Address = %#x, want the application's %#x", gotAddress, appAddress)
	}
}

// TestRmAllocInvalidClientCopiesOutRequest checks that NV_ESC_RM_ALLOC with an
// unknown client copies out the request the application passed, in its own
// layout, with NV_ERR_INVALID_CLIENT.
func TestRmAllocInvalidClientCopiesOutRequest(t *testing.T) {
	for _, tc := range []struct {
		name      string
		isNVOS64  bool
		size      uint32
		hasRights bool
	}{
		{"NVOS21_PARAMETERS", false, nvgpu.SizeofNVOS21Parameters, false},
		{"NVOS64_PARAMETERS", true, nvgpu.SizeofNVOS64Parameters, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fi := newTestIoctl(t)
			fi.nr = nvgpu.NV_ESC_RM_ALLOC
			fi.ioctlParamsSize = tc.size
			// The alloc parameters and rights that the request points to follow
			// it in the page.
			appAllocParams := nvgpu.P64(uint64(fi.ioctlParamsAddr) + 0x400)
			var appRights nvgpu.P64
			if tc.hasRights {
				appRights = nvgpu.P64(uint64(fi.ioctlParamsAddr) + 0x600)
			}
			params := nvgpu.NVOS64_PARAMETERS{
				HRoot:            nvgpu.Handle{Val: 0xc1d00001},
				HObjectParent:    nvgpu.Handle{Val: 0xc1d00001},
				HObjectNew:       nvgpu.Handle{Val: 0xcaf00001},
				HClass:           nvgpu.NV01_DEVICE_0,
				PAllocParms:      appAllocParams,
				PRightsRequested: appRights,
			}
			var allocParams nvgpu.NV0080_ALLOC_PARAMETERS
			if _, err := rmAllocInvoke(fi, &params, &allocParams, tc.isNVOS64, addSimpleObjDepParentLocked); err != nil {
				t.Fatalf("rmAllocInvoke failed: %v", err)
			}

			buf := make([]byte, 0x400)
			if _, err := fi.t.CopyInBytes(fi.ioctlParamsAddr, buf); err != nil {
				t.Fatalf("CopyInBytes failed: %v", err)
			}
			got := nvgpu.GetRmAllocParamObj(tc.isNVOS64)
			got.UnmarshalUnsafe(buf[:tc.size])
			if status := got.GetStatus(); status != nvgpu.NV_ERR_INVALID_CLIENT {
				t.Errorf("Status = %#x, want NV_ERR_INVALID_CLIENT (%#x)", status, nvgpu.NV_ERR_INVALID_CLIENT)
			}
			if p := got.GetPAllocParms(); p != appAllocParams {
				t.Errorf("pAllocParms = %#x, want the application's %#x", p, appAllocParams)
			}
			if p := got.GetPRightsRequested(); p != appRights {
				t.Errorf("pRightsRequested = %#x, want the application's %#x", p, appRights)
			}
			for i, b := range buf[tc.size:] {
				if b != testFiller {
					t.Fatalf("byte %d after the %d-byte request is %#x, want it unchanged", i, tc.size, b)
				}
			}
		})
	}
}
