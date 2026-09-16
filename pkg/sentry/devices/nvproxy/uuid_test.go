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
	"os"
	"reflect"
	"strings"
	"testing"
	"unsafe"

	"gvisor.dev/gvisor/pkg/abi/nvgpu"
	"gvisor.dev/gvisor/pkg/hostarch"
)

const (
	guestUUID = "GPU-01234567-89ab-cdef-fedc-ba9876543210"
	hostUUID  = "GPU-fedcba98-7654-3210-0123-456789abcdef"
)

// TestUUIDOffsetsFindEveryGPUUUID pins that the reflective walk finds the UUID
// in each UVM parameter type that carries one, including every element of
// UVM_MAP_EXTERNAL_ALLOCATION_PARAMS.PerGPUAttributes -- the ioctl whose stale
// UUID makes cuMemSetAccess() fail with CUDA_ERROR_INVALID_DEVICE.
func TestUUIDOffsetsFindEveryGPUUUID(t *testing.T) {
	for _, test := range []struct {
		name  string
		typ   reflect.Type
		count int
		first int
	}{
		{"UVM_REGISTER_GPU", reflect.TypeOf(nvgpu.UVM_REGISTER_GPU_PARAMS{}), 1, 0},
		{"UVM_UNREGISTER_GPU", reflect.TypeOf(nvgpu.UVM_UNREGISTER_GPU_PARAMS{}), 1, 0},
		{"UVM_REGISTER_GPU_VASPACE", reflect.TypeOf(nvgpu.UVM_REGISTER_GPU_VASPACE_PARAMS{}), 1, 0},
		{"UVM_ENABLE_PEER_ACCESS", reflect.TypeOf(nvgpu.UVM_ENABLE_PEER_ACCESS_PARAMS{}), 2, 0},
		{"UVM_DISABLE_PEER_ACCESS", reflect.TypeOf(nvgpu.UVM_DISABLE_PEER_ACCESS_PARAMS{}), 2, 0},
		{"UVM_MAP_EXTERNAL_ALLOCATION", reflect.TypeOf(nvgpu.UVM_MAP_EXTERNAL_ALLOCATION_PARAMS{}), nvgpu.UVM_MAX_GPUS, 24},
		{"UVM_MAP_EXTERNAL_ALLOCATION_V550", reflect.TypeOf(nvgpu.UVM_MAP_EXTERNAL_ALLOCATION_PARAMS_V550{}), nvgpu.UVM_MAX_GPUS_V2, 24},
		{"UVM_SET_PREFERRED_LOCATION", reflect.TypeOf(nvgpu.UVM_SET_PREFERRED_LOCATION_PARAMS{}), 1, -1},
		{"UVM_SET_ACCESSED_BY", reflect.TypeOf(nvgpu.UVM_SET_ACCESSED_BY_PARAMS{}), 1, -1},
		{"UVM_MIGRATE", reflect.TypeOf(nvgpu.UVM_MIGRATE_PARAMS{}), 1, -1},
		{"UVM_ALLOC_SEMAPHORE_POOL", reflect.TypeOf(nvgpu.UVM_ALLOC_SEMAPHORE_POOL_PARAMS{}), nvgpu.UVM_MAX_GPUS, -1},
		{"UVM_REGISTER_CHANNEL", reflect.TypeOf(nvgpu.UVM_REGISTER_CHANNEL_PARAMS{}), 1, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			offs := uuidOffsetsFor(test.typ)
			if len(offs) != test.count {
				t.Fatalf("uuidOffsetsFor(%s) found %d UUIDs, want %d (offsets %v)", test.name, len(offs), test.count, offs)
			}
			if test.first >= 0 && offs[0] != test.first {
				t.Errorf("uuidOffsetsFor(%s)[0] = %d, want %d", test.name, offs[0], test.first)
			}
			// Every offset must be inside the struct.
			for _, off := range offs {
				if off < 0 || off+uuidSize > int(test.typ.Size()) {
					t.Errorf("uuidOffsetsFor(%s) offset %d is outside a %d-byte struct", test.name, off, test.typ.Size())
				}
			}
		})
	}
}

// TestMapExternalAllocationUUIDRoundTrip drives the exact path that fails on a
// remapped restore: the application passes the UUID it had before the
// checkpoint, nvproxy resolves it to the host's for the driver, and puts the
// application's back before the application reads the struct again.
func TestMapExternalAllocationUUIDRoundTrip(t *testing.T) {
	guestBin, ok := uuidBinary(guestUUID)
	if !ok {
		t.Fatalf("uuidBinary(%q) failed", guestUUID)
	}
	hostBin, ok := uuidBinary(hostUUID)
	if !ok {
		t.Fatalf("uuidBinary(%q) failed", hostUUID)
	}

	var params nvgpu.UVM_MAP_EXTERNAL_ALLOCATION_PARAMS
	params.GPUAttributesCount = 1
	params.PerGPUAttributes[0].GPUUUID = nvgpu.NvUUID(guestBin)

	typ := reflect.TypeOf(&params).Elem()
	offs := uuidOffsetsFor(typ)
	buf := unsafe.Slice((*byte)(unsafe.Pointer(&params)), int(typ.Size()))

	guestToHost := map[string]string{guestUUID: hostUUID}
	hostToGuest := map[string]string{hostUUID: guestUUID}

	// Inward: the driver must see the host's UUID.
	if done := translateUUIDsInBuf(buf, offs, guestToHost); len(done) != 1 {
		t.Fatalf("translateUUIDsInBuf() made %d translations, want 1", len(done))
	}
	if params.PerGPUAttributes[0].GPUUUID != nvgpu.NvUUID(hostBin) {
		t.Fatalf("inward translation produced %s, want %s", formatUUID(params.PerGPUAttributes[0].GPUUUID[:]), hostUUID)
	}
	// Untouched slots must stay zero rather than being given a device.
	if params.PerGPUAttributes[1].GPUUUID != (nvgpu.NvUUID{}) {
		t.Errorf("an unused per-GPU slot was written: %s", formatUUID(params.PerGPUAttributes[1].GPUUUID[:]))
	}

	// Outward: the application must read back its own UUID.
	translateUUIDsInBuf(buf, offs, hostToGuest)
	if params.PerGPUAttributes[0].GPUUUID != nvgpu.NvUUID(guestBin) {
		t.Fatalf("outward translation produced %s, want %s", formatUUID(params.PerGPUAttributes[0].GPUUUID[:]), guestUUID)
	}
}

// TestUUIDTranslationLeavesUnknownDevicesAlone pins that a UUID the sandbox
// does not own is passed through rather than mapped onto some other device.
func TestUUIDTranslationLeavesUnknownDevicesAlone(t *testing.T) {
	const otherUUID = "GPU-99999999-9999-9999-9999-999999999999"
	otherBin, ok := uuidBinary(otherUUID)
	if !ok {
		t.Fatal("uuidBinary failed")
	}
	var params nvgpu.UVM_REGISTER_GPU_PARAMS
	params.GPUUUID = nvgpu.NvUUID(otherBin)
	typ := reflect.TypeOf(&params).Elem()
	buf := unsafe.Slice((*byte)(unsafe.Pointer(&params)), int(typ.Size()))
	if done := translateUUIDsInBuf(buf, uuidOffsetsFor(typ), map[string]string{guestUUID: hostUUID}); len(done) != 0 {
		t.Errorf("translateUUIDsInBuf() translated an unknown UUID: %v", done)
	}
	if params.GPUUUID != nvgpu.NvUUID(otherBin) {
		t.Errorf("an unknown UUID was modified")
	}
}

// TestNoUUIDMapIsANoOp pins that a sandbox that was never restored onto other
// devices pays nothing and changes nothing.
func TestNoUUIDMapIsANoOp(t *testing.T) {
	var params nvgpu.UVM_REGISTER_GPU_PARAMS
	guestBin, _ := uuidBinary(guestUUID)
	params.GPUUUID = nvgpu.NvUUID(guestBin)
	typ := reflect.TypeOf(&params).Elem()
	buf := unsafe.Slice((*byte)(unsafe.Pointer(&params)), int(typ.Size()))
	if done := translateUUIDsInBuf(buf, uuidOffsetsFor(typ), nil); done != nil {
		t.Errorf("translateUUIDsInBuf() with no map made translations: %v", done)
	}
	if params.GPUUUID != nvgpu.NvUUID(guestBin) {
		t.Errorf("params were modified with no map")
	}
}

// TestRawIDSpecsFitTheirParams pins that every modelled field lies inside the
// parameter size it was modelled from, so a translation cannot run off the end
// of the buffer.
func TestRawIDSpecsFitTheirParams(t *testing.T) {
	for cmd, spec := range rawIDSpecs {
		if got := spec.minSize(); got > spec.Size {
			t.Errorf("%s (cmd %#x): fields need %d bytes but the layout is %d", spec.Name, cmd, got, spec.Size)
		}
		for _, f := range spec.Fields {
			if f.CountAt >= 0 && f.CountAt+4 > spec.Size {
				t.Errorf("%s: CountAt %d is outside a %d-byte layout", spec.Name, f.CountAt, spec.Size)
			}
			if f.Count <= 0 {
				t.Errorf("%s: field has Count %d", spec.Name, f.Count)
			}
		}
	}
}

// TestApplyRawIDFieldsRoundTrip drives an inbound gpuId array through the
// translate/restore pair the raw handler uses.
func TestApplyRawIDFieldsRoundTrip(t *testing.T) {
	spec := rawIDSpecs[nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_P2P_CAPS_MATRIX]
	if spec == nil {
		t.Fatal("no spec for GET_P2P_CAPS_MATRIX")
	}
	buf := make([]byte, spec.Size)
	// grpACount = 2, grpBCount = 0; gpuIdGrpA = [0x1111, 0x2222, 0x3333, ...].
	putU32(buf, 0, 2)
	putU32(buf, 8, 0x1111)
	putU32(buf, 12, 0x2222)
	putU32(buf, 16, 0x3333)

	maps := idMaps{
		GuestToHostGPUID: map[uint32]uint32{0x1111: 0xaaaa, 0x2222: 0xbbbb, 0x3333: 0xcccc},
		HostToGuestGPUID: map[uint32]uint32{0xaaaa: 0x1111, 0xbbbb: 0x2222, 0xcccc: 0x3333},
	}
	if n := applyRawIDFields(buf, spec, idIn, false, maps, nil); n != 2 {
		t.Fatalf("applyRawIDFields() translated %d values, want 2 (grpACount bounds it)", n)
	}
	if got := getU32(buf, 8); got != 0xaaaa {
		t.Errorf("gpuIdGrpA[0] = %#x, want 0xaaaa", got)
	}
	if got := getU32(buf, 16); got != 0x3333 {
		t.Errorf("gpuIdGrpA[2] = %#x, want 0x3333 (beyond grpACount, must be untouched)", got)
	}
	if n := applyRawIDFields(buf, spec, idIn, true, maps, nil); n != 2 {
		t.Fatalf("restore translated %d values, want 2", n)
	}
	if got := getU32(buf, 8); got != 0x1111 {
		t.Errorf("after restore gpuIdGrpA[0] = %#x, want 0x1111", got)
	}
}

// TestApplyRawIDFieldsStride drives the strided gpuId field of
// GET_ACTIVE_DEVICE_IDS, whose entries are 12 bytes apart.
func TestApplyRawIDFieldsStride(t *testing.T) {
	spec := rawIDSpecs[nvgpu.NV0000_CTRL_CMD_GPU_GET_ACTIVE_DEVICE_IDS]
	if spec == nil {
		t.Fatal("no spec for GET_ACTIVE_DEVICE_IDS")
	}
	buf := make([]byte, spec.Size)
	putU32(buf, 0, 2) // numDevices
	putU32(buf, 4, 0xaaaa)
	putU32(buf, 8, 7) // gpuInstanceId, a MIG id: must not be translated
	putU32(buf, 16, 0xbbbb)
	maps := idMaps{HostToGuestGPUID: map[uint32]uint32{0xaaaa: 0x1111, 0xbbbb: 0x2222, 7: 0xdead}}
	if n := applyRawIDFields(buf, spec, idOut, false, maps, nil); n != 2 {
		t.Fatalf("applyRawIDFields() translated %d values, want 2", n)
	}
	if got := getU32(buf, 4); got != 0x1111 {
		t.Errorf("devices[0].gpuId = %#x, want 0x1111", got)
	}
	if got := getU32(buf, 16); got != 0x2222 {
		t.Errorf("devices[1].gpuId = %#x, want 0x2222", got)
	}
	if got := getU32(buf, 8); got != 7 {
		t.Errorf("devices[0].gpuInstanceId = %#x, want 7 (a MIG id, never translated)", got)
	}
}

// TestTranslateIDNeverTouchesInvalidID pins that the terminator of a gpuId
// array is left alone even if it somehow appears in a map.
func TestTranslateIDNeverTouchesInvalidID(t *testing.T) {
	m := map[uint32]uint32{nvgpu.NV0000_CTRL_GPU_INVALID_ID: 3}
	if got, ok := translateID(nvgpu.NV0000_CTRL_GPU_INVALID_ID, m); ok || got != nvgpu.NV0000_CTRL_GPU_INVALID_ID {
		t.Errorf("translateID(INVALID_ID) = (%#x, %v), want (INVALID_ID, false)", got, ok)
	}
}

func putU32(b []byte, off int, v uint32) {
	b[off] = byte(v)
	b[off+1] = byte(v >> 8)
	b[off+2] = byte(v >> 16)
	b[off+3] = byte(v >> 24)
}

func getU32(b []byte, off int) uint32 {
	return uint32(b[off]) | uint32(b[off+1])<<8 | uint32(b[off+2])<<16 | uint32(b[off+3])<<24
}

// TestScopeForNilTaskIsConservative pins that with no task to ask, nvproxy
// does not translate: passing host identities through unchanged is what it did
// before any translation existed, and is always safe.
func TestScopeForNilTaskIsConservative(t *testing.T) {
	scope := scopeFor(nil)
	if scope.Restored {
		t.Errorf("scopeFor(nil).Restored = true, want false")
	}
	if scope.TGID != 0 {
		t.Errorf("scopeFor(nil).TGID = %d, want 0", scope.TGID)
	}
}

func TestTranslationScopeString(t *testing.T) {
	if got, want := (translationScope{Restored: true, TGID: 42}).String(), "tgid=42 restored=true"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
	if got, want := (translationScope{}).String(), "tgid=0 restored=false"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

// TestEveryTranslationIsScoped reads the source and requires that each handler
// which translates an identifier also consults the translation scope. A
// translation that is not scoped hands a process created after the restore an
// identity, and a device file name, that does not exist -- which is how the
// unscoped version killed the sandbox on restore.
func TestEveryTranslationIsScoped(t *testing.T) {
	for _, test := range []struct {
		file  string
		funcs []string
	}{
		{"gpuid_frontend.go", []string{
			"func rmAllocDevice(",
			"func rmAllocMemoryExport(",
			"func ctrlTranslateRawIDs(",
			"func ctrlGpuGetIDInfoTranslate(",
			"func ctrlGpuGetIDInfoV2(",
			"func ctrlGpuAttachIDs(",
			"func ctrlGpuGetUUIDFromGPUID(",
			"func ctrlGpuGetGidInfo(",
		}},
		{"frontend.go", []string{"func ctrlGetExportObjectInfo[", "func (dev *frontendDevice) forOpeningTask("}},
		{"frontend_unsafe.go", []string{"func translateP2PGpuIDsToHost("}},
		{"uvm_unsafe.go", []string{"func uvmIoctlInvoke["}},
		{"pciaddr.go", []string{
			"func translateCardInfo(",
			"func ctrlGpuGetPCIInfo(",
			"func ctrlBusGetInfoV2(",
		}},
	} {
		src, err := os.ReadFile(test.file)
		if err != nil {
			t.Fatalf("reading %s: %v", test.file, err)
		}
		for _, fn := range test.funcs {
			body, ok := funcBody(string(src), fn)
			if !ok {
				t.Errorf("%s: could not find %q; if it was renamed, rename it here too", test.file, fn)
				continue
			}
			if !strings.Contains(body, "scope") {
				t.Errorf("%s: %q translates identifiers but never consults the translation scope", test.file, fn)
			}
		}
	}
}

// funcBody returns the text of the function whose declaration begins with
// decl, up to the closing brace in column 0.
func funcBody(src, decl string) (string, bool) {
	i := strings.Index(src, decl)
	if i < 0 {
		return "", false
	}
	rest := src[i:]
	if j := strings.Index(rest, "\n}\n"); j >= 0 {
		return rest[:j], true
	}
	return rest, true
}

// TestPermuteByDeviceInstance covers the array whose indices are device
// instances (NV00E0_ALLOCATION_PARAMETERS.GIIDMasks).
func TestPermuteByDeviceInstance(t *testing.T) {
	var arr [nvgpu.NV_MAX_DEVICES]uint32
	arr[0] = 0xaa
	arr[1] = 0xbb
	arr[9] = 0xcc
	// Guest instances 0,1 live at host instances 4,6.
	out := permuteByDeviceInstance(arr, map[uint32]uint32{0: 4, 1: 6})
	if out[4] != 0xaa || out[6] != 0xbb {
		t.Errorf("permuteByDeviceInstance() = [4]=%#x [6]=%#x, want 0xaa, 0xbb", out[4], out[6])
	}
	// An index named as a source, but not as a destination, is vacated.
	if out[0] != 0 || out[1] != 0 {
		t.Errorf("permuteByDeviceInstance() left [0]=%#x [1]=%#x, want both vacated", out[0], out[1])
	}
	// An index no translation names keeps its element.
	if out[9] != 0xcc {
		t.Errorf("permuteByDeviceInstance()[9] = %#x, want 0xcc", out[9])
	}
	// An empty map is the identity.
	if permuteByDeviceInstance(arr, nil) != arr {
		t.Errorf("permuteByDeviceInstance() with no map changed the array")
	}
}

// TestAllocParamsNoteNullDevice pins that the failure line distinguishes "the
// application passed no allocation parameters" from "it asked for device 0",
// which is the distinction the NV01_DEVICE_0 failure turned on.
func TestAllocParamsNoteNullDevice(t *testing.T) {
	if got, want := allocParamsNote(nvgpu.NV01_DEVICE_0, (*nvgpu.NV0080_ALLOC_PARAMETERS)(nil)), " deviceId=null"; got != want {
		t.Errorf("allocParamsNote(nil) = %q, want %q", got, want)
	}
	p := &nvgpu.NV0080_ALLOC_PARAMETERS{DeviceID: 3}
	if got, want := allocParamsNote(nvgpu.NV01_DEVICE_0, p), " deviceId=3"; got != want {
		t.Errorf("allocParamsNote() = %q, want %q", got, want)
	}
	if got := allocParamsNote(nvgpu.NV01_ROOT_CLIENT, nil); got != "" {
		t.Errorf("allocParamsNote() for an unremarkable class = %q, want empty", got)
	}
}

// TestNV0080AllocParamsDeviceIDOffset settles, against the real marshaller,
// that DeviceID is the first NvU32 of NV0080_ALLOC_PARAMETERS and that
// rmAllocDevice therefore reads and writes the field it means to. A
// mis-addressed read here would make every restored device object land on the
// wrong GPU while logging a plausible number.
func TestNV0080AllocParamsDeviceIDOffset(t *testing.T) {
	var p nvgpu.NV0080_ALLOC_PARAMETERS
	p.DeviceID = 0xa1a2a3a4
	p.HClientShare = nvgpu.Handle{Val: 0xb1b2b3b4}
	buf := make([]byte, p.SizeBytes())
	p.MarshalBytes(buf)

	if got := hostarch.ByteOrder.Uint32(buf[0:]); got != 0xa1a2a3a4 {
		t.Errorf("DeviceID marshalled to offset 0 as %#x, want 0xa1a2a3a4 (buf=%x)", got, buf[:16])
	}
	if got := hostarch.ByteOrder.Uint32(buf[4:]); got != 0xb1b2b3b4 {
		t.Errorf("HClientShare is not the second NvU32: got %#x (buf=%x)", got, buf[:16])
	}

	// Round-trip: what rmAllocDevice copies in is what the application wrote.
	var back nvgpu.NV0080_ALLOC_PARAMETERS
	back.UnmarshalBytes(buf)
	if back.DeviceID != p.DeviceID {
		t.Errorf("round-tripped DeviceID = %#x, want %#x", back.DeviceID, p.DeviceID)
	}

	// A zero value, which is what rmAllocDevice starts from when the
	// application passes no parameters at all, means device instance 0.
	var zero nvgpu.NV0080_ALLOC_PARAMETERS
	if zero.DeviceID != 0 {
		t.Errorf("the zero NV0080_ALLOC_PARAMETERS has DeviceID %d, want 0", zero.DeviceID)
	}
}

// TestIDInfoV2Offsets pins the byte offsets ctrlGpuGetIDInfoV2 addresses
// against the field order of NV0000_CTRL_GPU_GET_ID_INFO_V2_PARAMS
// {gpuId, gpuFlags, deviceInstance, subDeviceInstance, sliStatus, boardId,
// gpuInstance, numaId}, all bare NvU32.
func TestIDInfoV2Offsets(t *testing.T) {
	for _, test := range []struct {
		name  string
		off   int
		index int
	}{
		{"gpuId", idInfoV2GpuID, 0},
		{"deviceInstance", idInfoV2DeviceInstance, 2},
		{"subDeviceInstance", idInfoV2SubDeviceInstance, 3},
		{"gpuInstance", idInfoV2GpuInstance, 6},
	} {
		if want := test.index * 4; test.off != want {
			t.Errorf("%s is at offset %d, want %d (field %d of a flat NvU32 struct)", test.name, test.off, want, test.index)
		}
	}
	if idInfoV2ParamsSize != 8*4 {
		t.Errorf("idInfoV2ParamsSize = %d, want %d", idInfoV2ParamsSize, 8*4)
	}
	// The non-V2 struct is a different shape: it has an 8-byte szName pointer
	// in the middle, so these offsets must never be used for it.
	var v1 nvgpu.NV0000_CTRL_GPU_GET_ID_INFO_PARAMS
	if v1.SizeBytes() == idInfoV2ParamsSize {
		t.Errorf("NV0000_CTRL_GPU_GET_ID_INFO_PARAMS is %d bytes, the same as the V2 layout; the two handlers can no longer be told apart by size", v1.SizeBytes())
	}
}

// TestDescribeRawIDFieldStopsAtTerminator pins that the enumeration Debug line
// reports what the application will actually read, not the whole fixed array.
func TestDescribeRawIDFieldStopsAtTerminator(t *testing.T) {
	buf := make([]byte, 128)
	putU32(buf, 0, 0x4400)
	putU32(buf, 4, 0x300)
	putU32(buf, 8, nvgpu.NV0000_CTRL_GPU_INVALID_ID)
	putU32(buf, 12, 0x999)
	f := rawIDField{Kind: idGPUID, Dir: idOut, Offset: 0, Count: 32, CountAt: -1}
	if got, want := describeRawIDField(buf, f), "[17408, 768]"; got != want {
		t.Errorf("describeRawIDField() = %q, want %q", got, want)
	}
}

func TestEnumerationDoesNotAliasSourceAndDestinationGPUs(t *testing.T) {
	for _, cmd := range []uint32{nvgpu.NV0000_CTRL_CMD_GPU_GET_ATTACHED_IDS, nvgpu.NV0000_CTRL_CMD_GPU_GET_PROBED_IDS} {
		spec := rawIDSpecs[cmd]
		buf := make([]byte, spec.Size)
		for off := 0; off < len(buf); off += 4 {
			hostarch.ByteOrder.PutUint32(buf[off:], nvgpu.NV0000_CTRL_GPU_INVALID_ID)
		}
		input := []uint32{0x4400, 0x300, 0x400, 0x8300, 0xc400}
		for i, id := range input {
			hostarch.ByteOrder.PutUint32(buf[4*i:], id)
			if cmd == nvgpu.NV0000_CTRL_CMD_GPU_GET_PROBED_IDS {
				hostarch.ByteOrder.PutUint32(buf[256+4*i:], uint32(i+10))
			}
		}
		maps := idMaps{HostToGuestGPUID: map[uint32]uint32{0x8300: 0x400, 0xc400: 0x300}, GuestToHostGPUID: map[uint32]uint32{0x400: 0x8300, 0x300: 0xc400}}
		removeShadowedGPUIDs(buf, cmd, maps)
		applyRawIDFields(buf, spec, idOut, false, maps, nil)
		for i, want := range []uint32{0x4400, 0x400, 0x300, nvgpu.NV0000_CTRL_GPU_INVALID_ID} {
			if got := hostarch.ByteOrder.Uint32(buf[4*i:]); got != want {
				t.Fatalf("cmd=%#x entry %d=%#x, want %#x", cmd, i, got, want)
			}
		}
		if cmd == nvgpu.NV0000_CTRL_CMD_GPU_GET_PROBED_IDS {
			for i, want := range []uint32{10, 13, 14, 0} {
				if got := hostarch.ByteOrder.Uint32(buf[256+4*i:]); got != want {
					t.Fatalf("flags[%d]=%d, want %d", i, got, want)
				}
			}
		}
	}
}

func TestEnumerationPreservesOverlappingAndIdentityMappings(t *testing.T) {
	for _, hostToGuest := range []map[uint32]uint32{{1: 1, 2: 2}, {2: 1, 3: 2}, {2: 1, 1: 2}} {
		maps := idMaps{HostToGuestGPUID: hostToGuest, GuestToHostGPUID: make(map[uint32]uint32)}
		for host, guest := range hostToGuest {
			maps.GuestToHostGPUID[guest] = host
		}
		buf := make([]byte, 20)
		for i, id := range []uint32{1, 2, 3, 4, nvgpu.NV0000_CTRL_GPU_INVALID_ID} {
			hostarch.ByteOrder.PutUint32(buf[4*i:], id)
		}
		compactGPUIDList(buf, 0, 5, -1, maps)
		seen := make(map[uint32]bool)
		for i := 0; i < 5; i++ {
			id := hostarch.ByteOrder.Uint32(buf[4*i:])
			if id == nvgpu.NV0000_CTRL_GPU_INVALID_ID {
				break
			}
			if guest, ok := hostToGuest[id]; ok {
				id = guest
			}
			if seen[id] {
				t.Fatalf("mapping %v enumerates guest %d twice", hostToGuest, id)
			}
			seen[id] = true
		}
		for guest := range maps.GuestToHostGPUID {
			if !seen[guest] {
				t.Fatalf("mapping %v lost guest %d", hostToGuest, guest)
			}
		}
	}
}

// Admission needs the current composed map, scoped to the caller's CUDA identity.
func TestAdmissionGPUUUIDMap(t *testing.T) {
	nvp := &nvproxy{guestToHostUUID: map[string]string{guestUUID: hostUUID}}
	if got := nvp.gpuUUIDMap(translationScope{}); len(got) != 0 {
		t.Fatalf("fresh process map = %v, want empty", got)
	}
	restored := translationScope{Restored: true}
	got := nvp.gpuUUIDMap(restored)
	if got[guestUUID] != hostUUID {
		t.Fatalf("restored map = %v", got)
	}
	got[guestUUID] = "changed"
	if nvp.guestToHostUUID[guestUUID] != hostUUID {
		t.Fatal("caller mutated runtime mapping")
	}
	nvp.guestToHostUUID[guestUUID] = guestUUID
	if got := nvp.gpuUUIDMap(restored); got[guestUUID] != guestUUID {
		t.Fatalf("second migration map = %v", got)
	}
	var absent *nvproxy
	if got := absent.gpuUUIDMap(restored); len(got) != 0 {
		t.Fatalf("absent nvproxy map = %v", got)
	}
}
