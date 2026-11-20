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
	"slices"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/devices/nvproxy/nvconf"
)

// drmIOC encodes a DRM ioctl number like _IOC(dir, 'd', nr, size) in
// include/uapi/asm-generic/ioctl.h.
func drmIOC(dir, nr, size uint32) uint32 {
	return dir<<linux.IOC_DIRSHIFT | uint32('d')<<linux.IOC_TYPESHIFT | nr<<linux.IOC_NRSHIFT | size<<linux.IOC_SIZESHIFT
}

// TestDRMIoctlNumbers checks each render node ioctl number against its
// definition in include/uapi/drm/drm.h or
// kernel-open/nvidia-drm/nv_drm_common_ioctl.h, with the struct sizes of
// x86_64 and arm64. nvidia-drm's ioctls start at DRM_COMMAND_BASE (0x40).
func TestDRMIoctlNumbers(t *testing.T) {
	rw := uint32(linux.IOC_READ | linux.IOC_WRITE)
	for _, c := range []struct {
		name string
		got  uint32
		want uint32
	}{
		{"DRM_IOCTL_VERSION", drmIoctlVersion, drmIOC(rw, 0x00, 64)},
		{"DRM_IOCTL_GET_CAP", drmIoctlGetCap, drmIOC(rw, 0x0c, 16)},
		{"DRM_IOCTL_SET_CLIENT_CAP", drmIoctlSetClientCap, drmIOC(linux.IOC_WRITE, 0x0d, 16)},
		{"DRM_IOCTL_NVIDIA_GET_DEV_INFO with mig_device", (&drmABI{devInfoSize: 36}).getDevInfoCmd(), drmIOC(rw, 0x43, 36)},
		{"DRM_IOCTL_NVIDIA_FENCE_SUPPORTED", drmNvFenceSupported, drmIOC(linux.IOC_NONE, 0x44, 0)},
		{"DRM_IOCTL_NVIDIA_DMABUF_SUPPORTED", drmNvDmabufSupported, drmIOC(linux.IOC_NONE, 0x4f, 0)},
		{"DRM_IOCTL_NVIDIA_GET_DRM_FILE_UNIQUE_ID", drmNvGetDRMFileUniqueID, drmIOC(rw, 0x58, 8)},
	} {
		if c.got != c.want {
			t.Errorf("%s = %#x, want %#x", c.name, c.got, c.want)
		}
	}
}

// TestDRMOpensOnlyNvidiaDRM checks which driver names, as DRM_IOCTL_VERSION
// returns them, a render node may have for nvproxy to open it.
func TestDRMOpensOnlyNvidiaDRM(t *testing.T) {
	for _, c := range []struct {
		name    string
		copied  string
		nameLen uint64
		want    bool
	}{
		{"nvidia-drm", "nvidia-drm", 10, true},
		{"amdgpu", "amdgpu", 6, false},
		{"i915", "i915", 4, false},
		{"longer name with the same prefix", "nvidia-drm-", 14, false},
		{"truncated copy", "nvidia-d", 10, false},
		{"empty", "", 0, false},
	} {
		if got := isNvidiaDRMDriver([]byte(c.copied), c.nameLen); got != c.want {
			t.Errorf("%s: isNvidiaDRMDriver(%q, %d) = %v, want %v", c.name, c.copied, c.nameLen, got, c.want)
		}
	}
}

// TestDRMDevInfoLayout checks the size of struct drm_nvidia_get_dev_info_params,
// the offset of its first modeset=1 field and the presence of
// DRM_IOCTL_NVIDIA_GET_DRM_FILE_UNIQUE_ID in the driver versions around each
// change.
func TestDRMDevInfoLayout(t *testing.T) {
	Init()
	for _, c := range []struct {
		version nvconf.DriverVersion
		want    drmABI
	}{
		// gpu_id, primary_index, then generic_page_kind, page_kind_generation
		// and sector_layout.
		{nvconf.NewDriverVersion(535, 288, 1), drmABI{devInfoSize: 20, devInfoModesetOnly: 8}},
		// Adds supports_sync_fd and supports_semsurf.
		{nvconf.NewDriverVersion(545, 23, 6), drmABI{devInfoSize: 28, devInfoModesetOnly: 8}},
		// Adds supports_alloc after primary_index.
		{nvconf.NewDriverVersion(550, 90, 7), drmABI{devInfoSize: 32, devInfoModesetOnly: 8}},
		// Adds DRM_IOCTL_NVIDIA_GET_DRM_FILE_UNIQUE_ID.
		{nvconf.NewDriverVersion(555, 42, 2), drmABI{devInfoSize: 32, devInfoModesetOnly: 8, fileUniqueID: true}},
		{nvconf.NewDriverVersion(570, 195, 3), drmABI{devInfoSize: 32, devInfoModesetOnly: 8, fileUniqueID: true}},
		// Adds mig_device after gpu_id.
		{nvconf.NewDriverVersion(575, 51, 2), drmABI{devInfoSize: 36, devInfoModesetOnly: 12, fileUniqueID: true}},
		{nvconf.NewDriverVersion(610, 57, 4), drmABI{devInfoSize: 36, devInfoModesetOnly: 12, fileUniqueID: true}},
	} {
		entry, ok := abis[c.version]
		if !ok {
			t.Errorf("driver %v has no ABI", c.version)
			continue
		}
		if got := entry.cons().drm; got != c.want {
			t.Errorf("driver %v render node ABI = %+v, want %+v", c.version, got, c.want)
		}
	}
}

// TestDRMHostIoctlsCoverEveryDriver checks that the seccomp filters allow the
// DRM_IOCTL_NVIDIA_GET_DEV_INFO of every driver version.
func TestDRMHostIoctlsCoverEveryDriver(t *testing.T) {
	Init()
	host := drmHostIoctls()
	for version, entry := range abis {
		cmd := entry.cons().drm.getDevInfoCmd()
		if !slices.Contains(host, uintptr(cmd)) {
			t.Errorf("driver %v: DRM_IOCTL_NVIDIA_GET_DEV_INFO %#x is not in drmHostIoctls()", version, cmd)
		}
	}
}

// TestDRMHostIoctlsAreOnlyQueries checks that the render node ioctls that
// reach the host are exactly the queries DRM_IOCTL_VERSION,
// DRM_IOCTL_GET_CAP, DRM_IOCTL_SET_CLIENT_CAP and
// DRM_IOCTL_NVIDIA_GET_DEV_INFO in each of its sizes.
func TestDRMHostIoctlsAreOnlyQueries(t *testing.T) {
	rw := uint32(linux.IOC_READ | linux.IOC_WRITE)
	want := []uintptr{
		uintptr(drmIOC(rw, 0x00, 64)),
		uintptr(drmIOC(rw, 0x0c, 16)),
		uintptr(drmIOC(linux.IOC_WRITE, 0x0d, 16)),
		uintptr(drmIOC(rw, 0x43, 20)),
		uintptr(drmIOC(rw, 0x43, 28)),
		uintptr(drmIOC(rw, 0x43, 32)),
		uintptr(drmIOC(rw, 0x43, 36)),
	}
	if got := drmHostIoctls(); !slices.Equal(got, want) {
		t.Errorf("drmHostIoctls() = %#x, want %#x", got, want)
	}
}

// TestDRMDevInfoClearsModesetOnlyFields checks that
// DRM_IOCTL_NVIDIA_GET_DEV_INFO keeps the GPU's identity and clears what
// nvidia-drm sets only with modeset=1.
func TestDRMDevInfoClearsModesetOnlyFields(t *testing.T) {
	for _, abi := range []drmABI{
		{devInfoSize: 20, devInfoModesetOnly: 8},
		{devInfoSize: 36, devInfoModesetOnly: 12},
	} {
		buf := make([]byte, abi.devInfoSize)
		for i := range buf {
			buf[i] = 0xff
		}
		drmDevInfoAsModeset0(&abi, buf)
		for i, b := range buf {
			if uint32(i) < abi.devInfoModesetOnly && b != 0xff {
				t.Errorf("%+v: byte %d of the GPU's identity changed to %#x", abi, i, b)
			}
			if uint32(i) >= abi.devInfoModesetOnly && b != 0 {
				t.Errorf("%+v: byte %d of a modeset=1 field = %#x, want 0", abi, i, b)
			}
		}
	}
}

// TestDRMVersionRestoresApplicationPointersWhenTheHostCallFails checks that
// DRM_IOCTL_VERSION's struct keeps the application's string pointers, not the
// sentry's, after a host call that fails.
func TestDRMVersionRestoresApplicationPointersWhenTheHostCallFails(t *testing.T) {
	buf := make([]byte, drmVersionSize)
	for i, s := range drmVersionStrings {
		hostarch.ByteOrder.PutUint64(buf[s.ptrOff:], uint64(0x10000*(i+1)))
		hostarch.ByteOrder.PutUint64(buf[s.lenOff:], 8)
	}
	want := slices.Clone(buf)
	strs := [len(drmVersionStrings)][]byte{make([]byte, 8), nil, make([]byte, 8)}
	if _, err := drmVersionInvoke(-1, buf, &strs); err != unix.EBADF {
		t.Fatalf("drmVersionInvoke on fd -1 = %v, want EBADF", err)
	}
	if !slices.Equal(buf, want) {
		t.Errorf("struct drm_version after a failed host call = %x, want %x", buf, want)
	}
}

// TestDRMVersionGivesTheHostSentryBufferLengths checks that the host sees the
// length of each sentry buffer in DRM_IOCTL_VERSION's struct, whatever length
// the application gave, and the application's length for a string with no
// sentry buffer.
func TestDRMVersionGivesTheHostSentryBufferLengths(t *testing.T) {
	buf := make([]byte, drmVersionSize)
	for i, s := range drmVersionStrings {
		hostarch.ByteOrder.PutUint64(buf[s.ptrOff:], uint64(0x10000*(i+1)))
		hostarch.ByteOrder.PutUint64(buf[s.lenOff:], 1<<20)
	}
	strs := [len(drmVersionStrings)][]byte{make([]byte, 4), nil, make([]byte, 16)}
	if _, err := drmVersionInvoke(-1, buf, &strs); err != unix.EBADF {
		t.Fatalf("drmVersionInvoke on fd -1 = %v, want EBADF", err)
	}
	for i, s := range drmVersionStrings {
		want := uint64(1 << 20)
		if strs[i] != nil {
			want = uint64(len(strs[i]))
		}
		if got := hostarch.ByteOrder.Uint64(buf[s.lenOff:]); got != want {
			t.Errorf("length of string %d = %d, want %d", i, got, want)
		}
	}
}

func TestDRMFileIDsCountFromOne(t *testing.T) {
	var nvp nvproxy
	if got := nvp.nextDRMFileID(); got != 1 {
		t.Errorf("first DRM file ID = %d, want 1", got)
	}
}

func TestDRMFileIDsAreDistinctPerOpen(t *testing.T) {
	var nvp nvproxy
	first, second := nvp.nextDRMFileID(), nvp.nextDRMFileID()
	if first == second {
		t.Errorf("two opens share DRM file ID %d", first)
	}
}

func TestDRMFileIDsAreIndependentPerSandbox(t *testing.T) {
	var a, b nvproxy
	a.nextDRMFileID()
	a.nextDRMFileID()
	if got := b.nextDRMFileID(); got != 1 {
		t.Errorf("first DRM file ID in a second sandbox = %d, want 1", got)
	}
}
