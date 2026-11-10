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

// Package display_test tests the device files that the NVIDIA display driver
// capability exposes.
package display_test

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/docker/docker/api/types/container"
	"gvisor.dev/gvisor/pkg/test/dockerutil"
)

// displayProbe opens the render node in argv[1] and /dev/nvidia-modeset, and
// prints one "key value" line per result. argv[2], argv[3] and argv[4] are the
// fields of the driver's devInfoLayout.
const displayProbe = `
import ctypes, errno, mmap, os, sys

libc = ctypes.CDLL(None, use_errno=True)
libc.ioctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_void_p]

def ioctl(fd, cmd, arg):
    if libc.ioctl(fd, cmd, arg) < 0:
        return errno.errorcode[ctypes.get_errno()]
    return "OK"

def iowr(nr, size):
    return (3 << 30) | (size << 16) | (ord("d") << 8) | nr

class DRMVersion(ctypes.Structure):
    _fields_ = [("major", ctypes.c_int), ("minor", ctypes.c_int),
                ("patchlevel", ctypes.c_int),
                ("name_len", ctypes.c_size_t), ("name", ctypes.c_void_p),
                ("date_len", ctypes.c_size_t), ("date", ctypes.c_void_p),
                ("desc_len", ctypes.c_size_t), ("desc", ctypes.c_void_p)]

def probe_render_node(path):
    try:
        fd = os.open(path, os.O_RDWR)
    except OSError as e:
        print("render_open", errno.errorcode[e.errno])
        return
    print("render_open OK")

    name = ctypes.create_string_buffer(64)
    version = DRMVersion(name_len=len(name), name=ctypes.addressof(name))
    print("version", ioctl(fd, iowr(0x00, 64), ctypes.byref(version)))
    print("version_name", name.value.decode())

    size, modeset_only, alloc = int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
    info = ctypes.create_string_buffer(size)
    print("dev_info", ioctl(fd, iowr(0x43, size), info))
    if any(info.raw[modeset_only:]):
        print("modeset_fields set")
    else:
        print("modeset_fields zero")
    if alloc >= 0:
        print("supports_alloc", int.from_bytes(info.raw[alloc:alloc + 4], "little"))
    else:
        print("supports_alloc none")

    # DRM_IOCTL_NVIDIA_FENCE_SUPPORTED and DRM_IOCTL_NVIDIA_DMABUF_SUPPORTED.
    print("fence_supported", ioctl(fd, 0x6444, None))
    print("dmabuf_supported", ioctl(fd, 0x644f, None))

    # DRM_IOCTL_GEM_CLOSE of a handle that does not exist.
    handle = ctypes.create_string_buffer(8)
    print("gem_close", ioctl(fd, (1 << 30) | (8 << 16) | (ord("d") << 8) | 0x09, handle))

    try:
        mmap.mmap(fd, 4096)
        print("render_mmap OK")
    except OSError as e:
        print("render_mmap", errno.errorcode[e.errno])
    os.close(fd)

def probe_modeset():
    try:
        fd = os.open("/dev/nvidia-modeset", os.O_RDWR)
    except OSError as e:
        print("modeset_open", errno.errorcode[e.errno])
        return
    print("modeset_open OK")
    # NVKMS_IOCTL_CMD with a zeroed struct NvKmsIoctlParams.
    params = ctypes.create_string_buffer(16)
    print("modeset_ioctl", ioctl(fd, (3 << 30) | (16 << 16) | (ord("m") << 8), params))
    os.close(fd)

probe_render_node(sys.argv[1])
probe_modeset()
`

// nvidiaRenderNode returns the path of the render node of an NVIDIA GPU on the
// host, or "" if there is none.
func nvidiaRenderNode(t *testing.T) string {
	t.Helper()
	nodes, err := filepath.Glob("/sys/class/drm/renderD*")
	if err != nil {
		t.Fatalf("failed to list render nodes: %v", err)
	}
	for _, node := range nodes {
		vendor, err := os.ReadFile(filepath.Join(node, "device", "vendor"))
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(vendor)) == "0x10de" {
			return filepath.Join("/dev/dri", filepath.Base(node))
		}
	}
	return ""
}

// devInfoLayout is the layout of struct drm_nvidia_get_dev_info_params in a
// driver version.
type devInfoLayout struct {
	// size is the size of the struct, which DRM_IOCTL_NVIDIA_GET_DEV_INFO
	// encodes.
	size int
	// modesetOnly is the offset of the first field that nvidia-drm sets only
	// with modeset=1. All fields from it on are such fields.
	modesetOnly int
	// supportsAlloc is the offset of supports_alloc, or -1 if the struct has
	// none.
	supportsAlloc int
}

// hostDevInfoLayout returns the layout of struct
// drm_nvidia_get_dev_info_params in the host's NVIDIA driver. The struct is 20
// bytes before 545, 28 in 545.23, 32 from 545.29 (supports_alloc at 8) and 36
// from 575 (mig_device at 4, supports_alloc at 12). The host kernel accepts
// any size for the ioctl, so the probe must use the driver's own.
func hostDevInfoLayout(t *testing.T) devInfoLayout {
	t.Helper()
	version, err := os.ReadFile("/sys/module/nvidia/version")
	if err != nil {
		t.Fatalf("failed to read the NVIDIA driver version: %v", err)
	}
	fields := strings.SplitN(strings.TrimSpace(string(version)), ".", 3)
	if len(fields) < 2 {
		t.Fatalf("failed to parse the NVIDIA driver version %q", version)
	}
	major, err := strconv.Atoi(fields[0])
	if err != nil {
		t.Fatalf("failed to parse the NVIDIA driver version %q: %v", version, err)
	}
	minor, err := strconv.Atoi(fields[1])
	if err != nil {
		t.Fatalf("failed to parse the NVIDIA driver version %q: %v", version, err)
	}
	switch {
	case major < 545:
		return devInfoLayout{size: 20, modesetOnly: 8, supportsAlloc: -1}
	case major == 545 && minor < 29:
		return devInfoLayout{size: 28, modesetOnly: 8, supportsAlloc: -1}
	case major < 575:
		return devInfoLayout{size: 32, modesetOnly: 8, supportsAlloc: 8}
	default:
		return devInfoLayout{size: 36, modesetOnly: 12, supportsAlloc: 12}
	}
}

// displayAllowed returns true if the runtime's flags allow the display driver
// capability.
func displayAllowed() (bool, error) {
	args, err := dockerutil.RuntimeArgs()
	if err != nil {
		return false, err
	}
	for _, arg := range args {
		if caps, ok := strings.CutPrefix(strings.TrimLeft(arg, "-"), "nvproxy-allowed-driver-capabilities="); ok {
			return slices.Contains(strings.Split(caps, ","), "display"), nil
		}
	}
	return false, nil
}

// TestDisplayDevices checks the render node and /dev/nvidia-modeset that a
// container with the display capability gets, with runc and with gVisor.
// gVisor fails with ENXIO to open a device that nvproxy does not serve.
func TestDisplayDevices(t *testing.T) {
	ctx := context.Background()
	renderNode := nvidiaRenderNode(t)
	if renderNode == "" {
		t.Skip("no NVIDIA render node on the host; nvidia_drm is not loaded")
	}
	if _, err := os.Stat("/dev/nvidia-modeset"); err != nil {
		t.Skipf("no /dev/nvidia-modeset on the host: %v", err)
	}
	isGVisor, err := dockerutil.IsGVisorRuntime(ctx)
	if err != nil {
		t.Fatalf("failed to determine the runtime: %v", err)
	}
	if isGVisor {
		allowed, err := displayAllowed()
		if err != nil {
			t.Fatalf("failed to read the runtime's arguments: %v", err)
		}
		if !allowed {
			t.Skip("the runtime does not allow the display capability")
		}
	}

	c := dockerutil.MakeContainer(ctx, t)
	defer c.CleanUp(ctx)
	opts, err := dockerutil.GPURunOpts(dockerutil.SniffGPUOpts{
		Capabilities:         "compute,utility,graphics,display",
		DisableSnifferReason: "the sniffer does not know nvidia-drm ioctls",
	})
	if err != nil {
		t.Fatalf("failed to get GPU run options: %v", err)
	}
	opts.Image = "basic/python"
	opts.Entrypoint = []string{"python3"}
	for _, dev := range []string{renderNode, "/dev/nvidia-modeset"} {
		opts.Devices = append(opts.Devices, container.DeviceMapping{
			PathOnHost:        dev,
			PathInContainer:   dev,
			CgroupPermissions: "rwm",
		})
	}
	layout := hostDevInfoLayout(t)
	out, err := c.Run(ctx, opts, "-c", displayProbe, renderNode, strconv.Itoa(layout.size), strconv.Itoa(layout.modesetOnly), strconv.Itoa(layout.supportsAlloc))
	if err != nil {
		t.Fatalf("failed to run the probe: %v, output:\n%s", err, out)
	}
	t.Logf("probe output:\n%s", out)
	got := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if key, value, ok := strings.Cut(line, " "); ok {
			got[key] = value
		}
	}
	for _, tc := range []struct {
		name string
		// runcWant holds the probe results with runc.
		runcWant map[string]string
		// gVisorWant holds the probe results with gVisor.
		gVisorWant map[string]string
	}{
		{
			name: "render_node",
			runcWant: map[string]string{
				"render_open":  "OK",
				"version":      "OK",
				"version_name": "nvidia-drm",
				"dev_info":     "OK",
			},
			gVisorWant: map[string]string{
				"render_open": "ENXIO",
			},
		},
		{
			name: "nvidia_modeset",
			runcWant: map[string]string{
				"modeset_open": "OK",
			},
			gVisorWant: map[string]string{
				"modeset_open": "ENXIO",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := tc.runcWant
			if isGVisor {
				want = tc.gVisorWant
			}
			for key, value := range want {
				if got[key] != value {
					t.Errorf("%s = %q, want %q", key, got[key], value)
				}
			}
		})
	}
	// With either runtime, nvidia-drm offers dma-bufs only if it can
	// allocate, which only modeset=1 allows. Drivers whose struct has no
	// supports_alloc do not report whether it can.
	if layout.supportsAlloc >= 0 && (got["supports_alloc"] == "1") != (got["dmabuf_supported"] == "OK") {
		t.Errorf("supports_alloc = %s, but DRM_IOCTL_NVIDIA_DMABUF_SUPPORTED = %s", got["supports_alloc"], got["dmabuf_supported"])
	}
}
