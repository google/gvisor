// Copyright 2024 The gVisor Authors.
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

package sandboxsetup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

func TestShouldExposeNvidiaDevice(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "nvidiactl", path: "/dev/nvidiactl", want: true},
		{name: "nvidia-uvm", path: "/dev/nvidia-uvm", want: true},
		{name: "nvidia0", path: "/dev/nvidia0", want: true},
		{name: "nvidia1", path: "/dev/nvidia1", want: true},
		{name: "nvidia42", path: "/dev/nvidia42", want: true},
		{name: "nvidia-uvm-tools", path: "/dev/nvidia-uvm-tools", want: true},
		{name: "nvidia-modeset", path: "/dev/nvidia-modeset", want: false},
		{name: "not nvidia", path: "/dev/sda", want: false},
		{name: "nvidia prefix but not device", path: "/dev/nvidia-cap1", want: false},
		{name: "empty", path: "", want: false},
	}
	for _, tst := range tests {
		t.Run(tst.name, func(t *testing.T) {
			got := ShouldExposeNvidiaDevice(tst.path)
			if got != tst.want {
				t.Errorf("ShouldExposeNvidiaDevice(%q) = %v, want %v", tst.path, got, tst.want)
			}
		})
	}
}

func TestShouldExposeVFIODevice(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "vfio dir", path: "/dev/vfio/vfio", want: true},
		{name: "vfio group", path: "/dev/vfio/0", want: true},
		{name: "vfio dir itself", path: "/dev/vfio", want: true},
		{name: "not vfio", path: "/dev/sda", want: false},
		{name: "empty", path: "", want: false},
	}
	for _, tst := range tests {
		t.Run(tst.name, func(t *testing.T) {
			got := ShouldExposeVFIODevice(tst.path)
			if got != tst.want {
				t.Errorf("ShouldExposeVFIODevice(%q) = %v, want %v", tst.path, got, tst.want)
			}
		})
	}
}

func TestShouldExposeTpuDevice(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		// VFIO devices are always detected as TPU devices regardless of sysfs.
		{name: "vfio device", path: "/dev/vfio/0", want: true},
		{name: "vfio vfio", path: "/dev/vfio/vfio", want: true},
		{name: "not tpu", path: "/dev/sda", want: false},
		{name: "empty", path: "", want: false},
	}
	for _, tst := range tests {
		t.Run(tst.name, func(t *testing.T) {
			got := ShouldExposeTpuDevice(tst.path)
			if got != tst.want {
				t.Errorf("ShouldExposeTpuDevice(%q) = %v, want %v", tst.path, got, tst.want)
			}
		})
	}
}

func TestOpenCharDevice(t *testing.T) {
	// /dev/null stands in for an NVIDIA device: a test can create no device
	// files, but /dev/null is a character device, 1:3, on any Linux host.
	const nullMajor, nullMinor = 1, 3

	dir := t.TempDir()
	regular := filepath.Join(dir, "regular")
	if err := os.WriteFile(regular, nil, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink("/dev/null", link); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name    string
		src     string
		dev     specs.LinuxDevice
		wantErr string
	}{
		{name: "matching device", src: "/dev/null", dev: specs.LinuxDevice{Major: nullMajor, Minor: nullMinor}},
		{name: "other minor", src: "/dev/null", dev: specs.LinuxDevice{Major: nullMajor, Minor: nullMinor + 1}, wantErr: "is device 1:3, but the spec says 1:4"},
		{name: "other major", src: "/dev/null", dev: specs.LinuxDevice{Major: nullMajor + 1, Minor: nullMinor}, wantErr: "is device 1:3, but the spec says 2:3"},
		{name: "regular file", src: regular, dev: specs.LinuxDevice{Major: nullMajor, Minor: nullMinor}, wantErr: "is not a character device"},
		{name: "symlink to the device", src: link, dev: specs.LinuxDevice{Major: nullMajor, Minor: nullMinor}, wantErr: "is not a character device"},
		{name: "directory", src: dir, dev: specs.LinuxDevice{Major: nullMajor, Minor: nullMinor}, wantErr: "is not a character device"},
		{name: "missing", src: filepath.Join(dir, "missing"), dev: specs.LinuxDevice{Major: nullMajor, Minor: nullMinor}, wantErr: "no such file or directory"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, err := openCharDevice(tc.src, tc.dev, "/proc")
			if f != nil {
				defer f.Close()
			}
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("openCharDevice(%q, %+v) failed: %v", tc.src, tc.dev, err)
				}
				if !strings.HasPrefix(f.Name(), "/proc/self/fd/") {
					t.Errorf("openCharDevice(%q, %+v) returned a file named %q, want one named by its path under /proc/self/fd", tc.src, tc.dev, f.Name())
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("openCharDevice(%q, %+v) error = %v, want it to contain %q", tc.src, tc.dev, err, tc.wantErr)
			}
			if f != nil {
				t.Errorf("openCharDevice(%q, %+v) returned a file along with an error", tc.src, tc.dev)
			}
		})
	}
}
