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
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/specutils"
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

const inMountNSEnv = "SANDBOXSETUP_TEST_IN_MOUNT_NS"

// reexecInMountNS re-executes the current test in a new user and mount
// namespace if not already in one. It returns true if the caller is the parent
// process and should return immediately.
func reexecInMountNS(t *testing.T) bool {
	t.Helper()
	if os.Getenv(inMountNSEnv) != "" {
		if err := unix.Mount("", "/", "", unix.MS_SLAVE|unix.MS_REC, ""); err != nil {
			t.Fatalf("making mounts slave: %v", err)
		}
		return false
	}
	cmd := exec.Command("/proc/self/exe", "-test.run=^"+t.Name()+"$", "-test.v")
	cmd.Env = append(os.Environ(), inMountNSEnv+"=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  unix.CLONE_NEWUSER | unix.CLONE_NEWNS,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		if errors.Is(err, unix.EPERM) {
			t.Skipf("cannot create user and mount namespaces: %v", err)
		}
		t.Fatalf("child failed: %v\n%s", err, out)
	}
	return true
}

func TestSetupMountsNodev(t *testing.T) {
	if reexecInMountNS(t) {
		return
	}

	var devStatfs unix.Statfs_t
	if err := unix.Statfs("/dev", &devStatfs); err != nil {
		t.Fatalf("statfs(/dev): %v", err)
	}
	if devStatfs.Flags&unix.ST_NODEV != 0 {
		t.Skip("/dev is already mounted with ST_NODEV")
	}

	lisafsConf := specutils.GoferMountConf{
		Lower: specutils.Lisafs,
		Upper: specutils.NoOverlay,
	}

	tests := []struct {
		name      string
		policy    config.CharacterDevicePolicy
		wantNodev bool
	}{
		{
			name:      "EmulatedOnlySetsNodev",
			policy:    config.CharDevEmulatedOnly,
			wantNodev: true,
		},
		{
			name:      "PassthroughAllowsDev",
			policy:    config.CharDevPassthrough,
			wantNodev: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			conf := &config.Config{
				CharacterDevicePolicy: tc.policy,
			}
			mounts := []specs.Mount{
				{
					Source:      "/dev/null",
					Destination: "/dev_null",
					Type:        "bind",
				},
				{
					Source:      "/dev",
					Destination: "/mnt",
					Type:        "bind",
					Options:     []string{"rbind"},
				},
			}
			mountConfs := []specutils.GoferMountConf{lisafsConf, lisafsConf, lisafsConf}
			if err := SetupMounts(conf, mounts, root, "/proc", mountConfs, nil); err != nil {
				t.Fatalf("SetupMounts failed: %v", err)
			}
			for _, relDst := range []string{"dev_null", "mnt"} {
				dst := filepath.Join(root, relDst)
				t.Cleanup(func() {
					_ = unix.Unmount(dst, unix.MNT_DETACH)
				})

				var st unix.Statfs_t
				if err := unix.Statfs(dst, &st); err != nil {
					t.Fatalf("Statfs(%q): %v", dst, err)
				}
				if st.Flags&unix.ST_NOSUID == 0 {
					t.Errorf("Statfs(%q).Flags = %#x, want ST_NOSUID (%#x) set", dst, st.Flags, unix.ST_NOSUID)
				}
				gotNodev := st.Flags&unix.ST_NODEV != 0
				if gotNodev != tc.wantNodev {
					t.Errorf("Statfs(%q).Flags ST_NODEV = %v (flags=%#x), want %v", dst, gotNodev, st.Flags, tc.wantNodev)
				}
			}

			for _, devNull := range []string{
				filepath.Join(root, "dev_null"),
				filepath.Join(root, "mnt", "null"),
			} {
				f, openErr := os.OpenFile(devNull, os.O_RDONLY, 0)
				if f != nil {
					f.Close()
				}
				if tc.wantNodev {
					if !errors.Is(openErr, unix.EACCES) {
						t.Errorf("OpenFile(%q, O_RDONLY) = %v, want EACCES", devNull, openErr)
					}
				} else {
					if openErr != nil {
						t.Errorf("OpenFile(%q, O_RDONLY) = %v, want nil", devNull, openErr)
					}
				}
			}
		})
	}
}
