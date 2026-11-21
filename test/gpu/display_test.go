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
	"strings"
	"testing"

	"github.com/docker/docker/api/types/container"
	"gvisor.dev/gvisor/pkg/sentry/devices/nvproxy/nvconf"
	"gvisor.dev/gvisor/pkg/test/dockerutil"
)

// displayProbe opens the render node in argv[1] and /dev/nvidia-modeset, and
// prints one "key value" line per result.
const displayProbe = `
import ctypes, errno, os, sys

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
    print("version", ioctl(fd, iowr(0x00, ctypes.sizeof(DRMVersion)), ctypes.byref(version)))
    print("version_name", name.value.decode())
    os.close(fd)

def probe_modeset():
    try:
        fd = os.open("/dev/nvidia-modeset", os.O_RDWR)
    except OSError as e:
        print("modeset_open", errno.errorcode[e.errno])
        return
    print("modeset_open OK")
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

// displayAllowed returns true if the runtime's flags allow the display driver
// capability.
func displayAllowed() (bool, error) {
	conf, err := dockerutil.RuntimeConfig()
	if err != nil {
		return false, err
	}
	caps, _, err := nvconf.DriverCapsFromString(conf.NVProxyAllowedDriverCapabilities)
	if err != nil {
		return false, err
	}
	return caps&nvconf.CapDisplay != 0, nil
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
	out, err := c.Run(ctx, opts, "-c", displayProbe, renderNode)
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
		// want holds the probe results with runc, and with gVisor if
		// gVisorWant is nil.
		want map[string]string
		// gVisorWant holds the probe results with gVisor, or nil if they are
		// the same as want.
		gVisorWant map[string]string
	}{
		{
			name: "render_node",
			want: map[string]string{
				"render_open":  "OK",
				"version":      "OK",
				"version_name": "nvidia-drm",
			},
			gVisorWant: map[string]string{
				"render_open": "ENXIO",
			},
		},
		{
			name: "nvidia_modeset",
			want: map[string]string{
				"modeset_open": "OK",
			},
			gVisorWant: map[string]string{
				"modeset_open": "ENXIO",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := tc.want
			if isGVisor && tc.gVisorWant != nil {
				want = tc.gVisorWant
			}
			for key, value := range want {
				if got[key] != value {
					t.Errorf("%s = %q, want %q", key, got[key], value)
				}
			}
		})
	}
}
