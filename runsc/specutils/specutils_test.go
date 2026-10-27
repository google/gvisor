// Copyright 2018 The gVisor Authors.
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

package specutils

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/sentry/devices/nvproxy/nvconf"
	"gvisor.dev/gvisor/runsc/config"
)

func TestIsProcessRunning(t *testing.T) {
	for _, tc := range []struct {
		pid  int
		want bool
	}{
		{pid: 0, want: false},
		{pid: -1, want: false},
		{pid: os.Getpid(), want: true},
	} {
		if got, err := IsProcessRunning(tc.pid, 0); err != nil || got != tc.want {
			t.Errorf("IsProcessRunning(%d) = (%t, %v), want (%t, nil)", tc.pid, got, err, tc.want)
		}
	}

	cmd := exec.Command("/bin/true")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
	})
	pid := cmd.Process.Pid
	// Wait for exit without reaping the child so the zombie remains observable.
	_, _, err := RetryEintr(func() (uintptr, uintptr, error) {
		_, _, errno := unix.Syscall6(unix.SYS_WAITID, unix.P_PID, uintptr(pid), 0, unix.WEXITED|unix.WNOWAIT, 0, 0)
		if errno != 0 {
			return 0, 0, errno
		}
		return 0, 0, nil
	})
	if err != nil {
		t.Fatalf("waitid(%d): %v", pid, err)
	}
	if got, err := IsProcessRunning(pid, 0); err != nil || got {
		t.Errorf("IsProcessRunning(%d) for zombie = (%t, %v), want (false, nil)", pid, got, err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	if got, err := IsProcessRunning(pid, 0); err != nil || got {
		t.Errorf("IsProcessRunning(%d) after reaping = (%t, %v), want (false, nil)", pid, got, err)
	}
}

func TestWaitForReadyHappy(t *testing.T) {
	cmd := exec.Command("/bin/sleep", "1000")
	if err := cmd.Start(); err != nil {
		t.Fatalf("cmd.Start() failed, err: %v", err)
	}
	defer func() { _ = cmd.Wait() }()

	var count int
	err := WaitForReady(cmd.Process.Pid, 5*time.Second, func() (bool, error) {
		if count < 3 {
			count++
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		t.Errorf("ProcessWaitReady got: %v, expected: nil", err)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Errorf("cmd.ProcessKill(): %v", err)
	}
}

func TestWaitForReadyFail(t *testing.T) {
	cmd := exec.Command("/bin/sleep", "1000")
	if err := cmd.Start(); err != nil {
		t.Fatalf("cmd.Start() failed, err: %v", err)
	}
	defer func() { _ = cmd.Wait() }()

	var count int
	err := WaitForReady(cmd.Process.Pid, 5*time.Second, func() (bool, error) {
		if count < 3 {
			count++
			return false, nil
		}
		return false, fmt.Errorf("fake error")
	})
	if err == nil {
		t.Errorf("ProcessWaitReady got: nil, expected: error")
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Errorf("cmd.ProcessKill(): %v", err)
	}
}

func TestWaitForReadyNotRunning(t *testing.T) {
	cmd := exec.Command("/bin/true")
	if err := cmd.Start(); err != nil {
		t.Fatalf("cmd.Start() failed, err: %v", err)
	}
	defer func() { _ = cmd.Wait() }()

	err := WaitForReady(cmd.Process.Pid, 5*time.Second, func() (bool, error) {
		return false, nil
	})
	if err != nil && !strings.Contains(err.Error(), "terminated") {
		t.Errorf("ProcessWaitReady got: %v, expected: process terminated", err)
	}
	if err == nil {
		t.Errorf("ProcessWaitReady incorrectly succeeded")
	}
}

func TestWaitForReadyTimeout(t *testing.T) {
	cmd := exec.Command("/bin/sleep", "1000")
	if err := cmd.Start(); err != nil {
		t.Fatalf("cmd.Start() failed, err: %v", err)
	}
	defer func() { _ = cmd.Wait() }()

	err := WaitForReady(cmd.Process.Pid, 50*time.Millisecond, func() (bool, error) {
		return false, nil
	})
	if err == nil || !strings.Contains(err.Error(), "not running yet") {
		t.Errorf("ProcessWaitReady got: %v, expected: not running yet", err)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Errorf("cmd.ProcessKill(): %v", err)
	}
}

func TestSpecInvalid(t *testing.T) {
	for _, test := range []struct {
		name            string
		spec            specs.Spec
		conf            config.Config
		noRootContainer bool
		error           string
	}{
		{
			name: "valid",
			spec: specs.Spec{
				Root: &specs.Root{Path: "/"},
				Process: &specs.Process{
					Args: []string{"/bin/true"},
				},
				Mounts: []specs.Mount{
					{
						Source:      "src",
						Destination: "/dst",
					},
				},
			},
			error: "",
		},
		{
			name: "valid+warning",
			spec: specs.Spec{
				Root: &specs.Root{Path: "/"},
				Process: &specs.Process{
					Args: []string{"/bin/true"},
					// This is normally set by docker and will just cause warnings to be logged.
					ApparmorProfile: "someprofile",
				},
				// This is normally set by docker and will just cause warnings to be logged.
				Linux: &specs.Linux{Seccomp: &specs.LinuxSeccomp{}},
			},
			error: "",
		},
		{
			name: "valid with no uts namespace",
			spec: specs.Spec{
				Root: &specs.Root{Path: "/"},
				Process: &specs.Process{
					Args: []string{"/bin/true"},
				},
				Linux: &specs.Linux{
					Namespaces: []specs.LinuxNamespace{
						{Type: specs.PIDNamespace},
					},
				},
			},
			error: "",
		},
		{
			name: "valid with new uts namespace",
			spec: specs.Spec{
				Root: &specs.Root{Path: "/"},
				Process: &specs.Process{
					Args: []string{"/bin/true"},
				},
				Linux: &specs.Linux{
					Namespaces: []specs.LinuxNamespace{
						{Type: specs.UTSNamespace},
					},
				},
			},
			error: "",
		},
		{
			name: "host uts namespace",
			spec: specs.Spec{
				Root: &specs.Root{Path: "/"},
				Process: &specs.Process{
					Args: []string{"/bin/true"},
				},
				Linux: &specs.Linux{
					Namespaces: []specs.LinuxNamespace{
						{Type: specs.UTSNamespace, Path: "/proc/1/ns/uts"},
					},
				},
			},
			error: "joining UTS namespace",
		},
		{
			name: "subcontainer with sandbox uts namespace",
			spec: specs.Spec{
				Root: &specs.Root{Path: "/"},
				Process: &specs.Process{
					Args: []string{"/bin/true"},
				},
				Annotations: map[string]string{
					ContainerdContainerTypeAnnotation: ContainerdContainerTypeContainer,
					ContainerdSandboxIDAnnotation:     "sandbox-123",
				},
				Linux: &specs.Linux{
					Namespaces: []specs.LinuxNamespace{
						{Type: specs.UTSNamespace, Path: "/proc/1234/ns/uts"},
					},
				},
			},
			error: "",
		},
		{
			name: "no root",
			spec: specs.Spec{
				Process: &specs.Process{
					Args: []string{"/bin/true"},
				},
			},
			error: "must be defined",
		},
		{
			name: "empty root",
			spec: specs.Spec{
				Root: &specs.Root{},
				Process: &specs.Process{
					Args: []string{"/bin/true"},
				},
			},
			error: "must be defined",
		},
		{
			name: "no process",
			spec: specs.Spec{
				Root: &specs.Root{Path: "/"},
			},
			error: "must be defined",
		},
		{
			name: "empty args",
			spec: specs.Spec{
				Root:    &specs.Root{Path: "/"},
				Process: &specs.Process{},
			},
			error: "must be defined",
		},
		{
			name: "selinux",
			spec: specs.Spec{
				Root: &specs.Root{Path: "/"},
				Process: &specs.Process{
					Args:         []string{"/bin/true"},
					SelinuxLabel: "somelabel",
				},
			},
			error: "is not supported",
		},
		{
			name: "solaris",
			spec: specs.Spec{
				Root: &specs.Root{Path: "/"},
				Process: &specs.Process{
					Args: []string{"/bin/true"},
				},
				Solaris: &specs.Solaris{},
			},
			error: "is not supported",
		},
		{
			name: "windows",
			spec: specs.Spec{
				Root: &specs.Root{Path: "/"},
				Process: &specs.Process{
					Args: []string{"/bin/true"},
				},
				Windows: &specs.Windows{},
			},
			error: "is not supported",
		},
		{
			name: "relative mount destination",
			spec: specs.Spec{
				Root: &specs.Root{Path: "/"},
				Process: &specs.Process{
					Args: []string{"/bin/true"},
				},
				Mounts: []specs.Mount{
					{
						Source:      "src",
						Destination: "dst",
					},
				},
			},
			error: "must be an absolute path",
		},
		{
			name: "invalid mount option",
			spec: specs.Spec{
				Root: &specs.Root{Path: "/"},
				Process: &specs.Process{
					Args: []string{"/bin/true"},
				},
				Mounts: []specs.Mount{
					{
						Source:      "/src",
						Destination: "/dst",
						Type:        "bind",
						Options:     []string{"shared"},
					},
				},
			},
			error: "is not supported",
		},
		{
			name: "invalid rootfs propagation",
			spec: specs.Spec{
				Root: &specs.Root{Path: "/"},
				Process: &specs.Process{
					Args: []string{"/bin/true"},
				},
				Linux: &specs.Linux{
					RootfsPropagation: "foo",
				},
			},
			error: "root mount propagation option must specify private or slave",
		},
		{
			name: "valid rootfs tar upper path",
			spec: specs.Spec{
				Root: &specs.Root{Path: "/"},
				Process: &specs.Process{
					Args: []string{"/bin/true"},
				},
				Annotations: map[string]string{
					AnnotationRootfsUpperTar: "foo",
				},
			},
			conf: config.Config{
				AllowRootfsTarAnnotation: true,
			},
			error: "",
		},
		{
			name: "invalid rootfs tar upper path",
			spec: specs.Spec{
				Root: &specs.Root{Path: "/"},
				Process: &specs.Process{
					Args: []string{"/bin/true"},
				},
				Annotations: map[string]string{
					AnnotationRootfsUpperTar: "foo",
				},
			},
			conf: config.Config{
				AllowRootfsTarAnnotation: false,
			},
			error: "rootfs tar annotation is disabled, use --allow-rootfs-tar-annotation to enable it",
		},
		{
			name: "readonly rootfs with tar upper annotation enabled",
			spec: specs.Spec{
				Root: &specs.Root{
					Readonly: true,
					Path:     "/",
				},
				Process: &specs.Process{
					Args: []string{"/bin/true"},
				},
				Annotations: map[string]string{
					AnnotationRootfsUpperTar: "foo",
				},
			},
			conf: config.Config{
				AllowRootfsTarAnnotation: true,
			},
			error: "rootfs tar upper path is set but rootfs is readonly",
		},
		{
			name: "sandbox spec",
			spec: specs.Spec{
				Hostname: "pod",
				Linux: &specs.Linux{
					CgroupsPath: "/kubepods/pod123",
					Namespaces: []specs.LinuxNamespace{
						{Type: specs.NetworkNamespace, Path: "/var/run/netns/cni-1"},
					},
				},
			},
			noRootContainer: true,
			error:           "",
		},
		{
			name: "sandbox spec with process",
			spec: specs.Spec{
				Process: &specs.Process{
					Args: []string{"/bin/true"},
				},
			},
			noRootContainer: true,
			error:           "Spec.Process must not be defined",
		},
		{
			name: "sandbox spec with root",
			spec: specs.Spec{
				Root: &specs.Root{Path: "/"},
			},
			noRootContainer: true,
			error:           "Spec.Root must not be defined",
		},
		{
			name: "sandbox spec still validates mounts",
			spec: specs.Spec{
				Mounts: []specs.Mount{
					{
						Source:      "src",
						Destination: "dst", // Not absolute.
					},
				},
			},
			noRootContainer: true,
			error:           "Mount.Destination must be an absolute path",
		},
		{
			name: "sandbox spec rejects unsupported fields",
			spec: specs.Spec{
				Windows: &specs.Windows{},
			},
			noRootContainer: true,
			error:           "Spec.Windows is not supported",
		},
	} {
		err := ValidateSpec(&test.spec, &test.conf, test.noRootContainer)
		if len(test.error) == 0 {
			if err != nil {
				t.Errorf("ValidateSpec(%q) failed, err: %v", test.name, err)
			}
		} else {
			if err == nil || !strings.Contains(err.Error(), test.error) {
				t.Errorf("ValidateSpec(%q) wrong error, got: %v, want: .*%s.*", test.name, err, test.error)
			}
		}
	}
}

func TestSeccomp(t *testing.T) {
	const containerName = "cont1"
	for _, tc := range []struct {
		name           string
		spec           specs.Spec
		seccompPresent bool
	}{
		{
			name:           "seccomp set",
			seccompPresent: true,
			spec: specs.Spec{
				Annotations: map[string]string{
					ContainerdContainerNameAnnotation: containerName,
				},
				Linux: &specs.Linux{
					Seccomp: &specs.LinuxSeccomp{},
				},
			},
		},
		{
			name:           "another container",
			seccompPresent: true,
			spec: specs.Spec{
				Annotations: map[string]string{
					ContainerdContainerNameAnnotation: containerName,
					annotationSeccomp + "cont2":       annotationSeccompRuntimeDefault,
				},
				Linux: &specs.Linux{
					Seccomp: &specs.LinuxSeccomp{},
				},
			},
		},
		{
			name:           "not RuntimeDefault",
			seccompPresent: true,
			spec: specs.Spec{
				Annotations: map[string]string{
					ContainerdContainerNameAnnotation: containerName,
					annotationSeccomp + containerName: "foobar",
				},
				Linux: &specs.Linux{
					Seccomp: &specs.LinuxSeccomp{},
				},
			},
		},
		{
			name:           "not RuntimeDefault many names",
			seccompPresent: true,
			spec: specs.Spec{
				Annotations: map[string]string{
					ContainerdContainerNameAnnotation: containerName,
					annotationSeccomp + containerName: "foobar",
					annotationSeccomp + "cont2":       annotationSeccompRuntimeDefault,
				},
				Linux: &specs.Linux{
					Seccomp: &specs.LinuxSeccomp{},
				},
			},
		},
		{
			name: "remove",
			spec: specs.Spec{
				Annotations: map[string]string{
					ContainerdContainerNameAnnotation: containerName,
					annotationSeccomp + containerName: annotationSeccompRuntimeDefault,
				},
				Linux: &specs.Linux{
					Seccomp: &specs.LinuxSeccomp{},
				},
			},
		},
		{
			name: "remove many names",
			spec: specs.Spec{
				Annotations: map[string]string{
					ContainerdContainerNameAnnotation: containerName,
					annotationSeccomp + containerName: annotationSeccompRuntimeDefault,
					annotationSeccomp + "cont2":       "foobar",
				},
				Linux: &specs.Linux{
					Seccomp: &specs.LinuxSeccomp{},
				},
			},
		},
		{
			name: "remap does not affect seccomp",
			spec: specs.Spec{
				Annotations: map[string]string{
					ContainerdContainerNameAnnotation:  containerName,
					annotationSeccomp + containerName:  annotationSeccompRuntimeDefault,
					annotationContainerNameRemap + "1": containerName + "=another",
				},
				Linux: &specs.Linux{
					Seccomp: &specs.LinuxSeccomp{},
				},
			},
		},
		{
			name: "remove-nonexistent",
			spec: specs.Spec{
				Annotations: map[string]string{
					annotationSeccomp + containerName: annotationSeccompRuntimeDefault,
				},
			},
		},
		{
			name: "empty",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.spec.Root = &specs.Root{}
			fixSpec(&tc.spec, "", nil)
			if tc.seccompPresent {
				if tc.spec.Linux == nil || tc.spec.Linux.Seccomp == nil {
					t.Errorf("seccomp is not in the spec: %+v", tc.spec)
				}
			} else if tc.spec.Linux != nil && tc.spec.Linux.Seccomp != nil {
				t.Errorf("seccomp is in the spec: %+v", tc.spec)
			}
		})
	}
}

func TestNvidiaDriverCapabilities(t *testing.T) {
	testAllowedCapsFlag := "utility,compute,graphics"
	testAllowedCaps, _, err := nvconf.DriverCapsFromString(testAllowedCapsFlag)
	if err != nil {
		t.Fatalf("nvconf.DriverCapsFromString(%q) failed: %v", testAllowedCapsFlag, err)
	}
	for _, tc := range []struct {
		name        string
		allowedCaps string
		wantAllowed nvconf.DriverCaps // Capabilities allowed at the sandbox configuration level.
		noEnv       bool              // If true, no env variable is set.
		envCaps     string
		legacy      bool
		wantActual  nvconf.DriverCaps // Capabilities allowed for the container.
	}{
		{
			name:        "unspecified",
			allowedCaps: testAllowedCapsFlag,
			wantAllowed: testAllowedCaps,
			noEnv:       true,
			wantActual:  nvconf.DefaultDriverCaps,
		},
		{
			name:        "unspecified-legacy",
			allowedCaps: testAllowedCapsFlag,
			wantAllowed: testAllowedCaps,
			noEnv:       true,
			legacy:      true,
			wantActual:  testAllowedCaps,
		},
		{
			name:        "empty",
			allowedCaps: testAllowedCapsFlag,
			wantAllowed: testAllowedCaps,
			envCaps:     "",
			wantActual:  nvconf.DefaultDriverCaps,
		},
		{
			name:        "empty-legacy",
			allowedCaps: testAllowedCapsFlag,
			wantAllowed: testAllowedCaps,
			envCaps:     "",
			legacy:      true,
			wantActual:  nvconf.DefaultDriverCaps,
		},
		{
			name:        "compute",
			allowedCaps: testAllowedCapsFlag,
			wantAllowed: testAllowedCaps,
			envCaps:     nvconf.CapCompute.String(),
			wantActual:  nvconf.CapCompute,
		},
		{
			name:        "utility,graphics-legacy",
			allowedCaps: testAllowedCapsFlag,
			wantAllowed: testAllowedCaps,
			envCaps:     (nvconf.CapUtility | nvconf.CapGraphics).String(),
			legacy:      true,
			wantActual:  nvconf.CapUtility | nvconf.CapGraphics,
		},
		{
			name:        "all",
			allowedCaps: testAllowedCapsFlag,
			wantAllowed: testAllowedCaps,
			envCaps:     nvconf.AllCapabilitiesName,
			wantActual:  testAllowedCaps,
		},
		{
			name:        "all-all",
			allowedCaps: nvconf.AllCapabilitiesName,
			wantAllowed: nvconf.AllContainerDriverCaps,
			envCaps:     nvconf.AllCapabilitiesName,
			wantActual:  nvconf.AllContainerDriverCaps,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conf := config.Config{NVProxyAllowedDriverCapabilities: tc.allowedCaps}
			allowed, err := NVProxyDriverCapsAllowed(&conf)
			if err != nil {
				t.Errorf("NVProxyDriverCapsAllowed() failed, err: %v", err)
			}
			if allowed != tc.wantAllowed {
				t.Fatalf("NVProxyDriverCapsAllowed() got: %v, want: %v", allowed, tc.wantAllowed)
			}
			var env []string
			if tc.legacy {
				env = append(env, fmt.Sprintf("%s=%s", cudaVersionEnv, "10.2.89"))
			}
			if tc.envCaps != "" || !tc.noEnv {
				env = append(env, fmt.Sprintf("%s=%s", nvidiaDriverCapsEnv, tc.envCaps))
			}
			spec := specs.Spec{Process: &specs.Process{Env: env}}
			got, err := NVProxyDriverCapsFromEnv(&spec, &conf)
			if err != nil {
				t.Errorf("NVProxyDriverCapsFromEnv() failed, err: %v", err)
			}
			if got != tc.wantActual {
				t.Errorf("NVProxyDriverCapsFromEnv() got: %v, want: %v", got, tc.wantActual)
			}
			// Check invariant: `got` must always be a subset of `allowed`.
			if gotButNotAllowed := got & ^allowed; gotButNotAllowed != 0 {
				t.Errorf("caps from env (%v) is not a subset of allowed caps (%v); diff: %v", got, allowed, gotButNotAllowed)
			}
		})
	}
}

func TestRootfsUpperTarPath(t *testing.T) {
	for _, tc := range []struct {
		name string
		spec specs.Spec
		want string
	}{
		{
			name: "no annotation",
			spec: specs.Spec{},
			want: "",
		},
		{
			name: "no gvisor tar rootfs upper annotation",
			spec: specs.Spec{
				Annotations: map[string]string{
					"dev.gvisor": "123",
				},
			},
			want: "",
		},
		{
			name: "get gvisor tar rootfs upper annotation",
			spec: specs.Spec{
				Annotations: map[string]string{
					AnnotationRootfsUpperTar: "123",
				},
			},
			want: "123",
		},
		{
			name: "container specific rootfs upper annotation",
			spec: specs.Spec{
				Annotations: map[string]string{
					ContainerdContainerNameAnnotation:       "cont",
					AnnotationRootfsUpperTar + "." + "cont": "456",
				},
			},
			want: "456",
		},
		{
			name: "container specific rootfs upper annotation with remap",
			spec: specs.Spec{
				Annotations: map[string]string{
					ContainerdContainerNameAnnotation:       "cont-123",
					annotationContainerNameRemap + "1":      "cont-123=cont",
					AnnotationRootfsUpperTar + "." + "cont": "789",
				},
			},
			want: "789",
		},
		{
			name: "no fallback when other container-specific annotation exists",
			spec: specs.Spec{
				Annotations: map[string]string{
					ContainerdContainerNameAnnotation:        "cont",
					AnnotationRootfsUpperTar + "." + "other": "should-not-be-used",
					AnnotationRootfsUpperTar:                 "base",
				},
			},
			want: "",
		},
		{
			name: "container specific takes priority over base",
			spec: specs.Spec{
				Annotations: map[string]string{
					ContainerdContainerNameAnnotation:       "cont",
					AnnotationRootfsUpperTar:                "base-path",
					AnnotationRootfsUpperTar + "." + "cont": "specific-path",
				},
			},
			want: "specific-path",
		},
		{
			name: "empty container name falls back to base",
			spec: specs.Spec{
				Annotations: map[string]string{
					ContainerdContainerNameAnnotation: "",
					AnnotationRootfsUpperTar:          "base-path",
				},
			},
			want: "base-path",
		},
		{
			name: "container name set but no matching annotation",
			spec: specs.Spec{
				Annotations: map[string]string{
					ContainerdContainerNameAnnotation: "cont",
					AnnotationRootfsUpperTar:          "base-path",
				},
			},
			want: "",
		},
		{
			name: "CRI sandbox without container name returns empty",
			spec: specs.Spec{
				Annotations: map[string]string{
					ContainerdContainerTypeAnnotation: ContainerdContainerTypeSandbox,
					AnnotationRootfsUpperTar:          "base-path",
				},
			},
			want: "",
		},
		{
			name: "CRI container without container name returns empty",
			spec: specs.Spec{
				Annotations: map[string]string{
					ContainerdContainerTypeAnnotation: ContainerdContainerTypeContainer,
					AnnotationRootfsUpperTar:          "base-path",
				},
			},
			want: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := RootfsTarUpperPath(&tc.spec)
			if got != tc.want {
				t.Errorf("RootfsUpperTarFD() got: %v, want: %v", got, tc.want)
			}
		})
	}
}

func TestIsProcFDPath(t *testing.T) {
	for _, tc := range []struct {
		name string
		path string
		want bool
	}{
		{name: "proc-self-fd", path: "/proc/self/fd/3", want: true},
		{name: "proc-thread-self-fd", path: "/proc/thread-self/fd/4", want: true},
		{name: "dev-fd", path: "/dev/fd/5", want: true},
		{name: "empty-fd", path: "/proc/self/fd/", want: false},
		{name: "non-numeric", path: "/proc/self/fd/abc", want: false},
		{name: "path-traversal", path: "/proc/self/fd/../etc/passwd", want: false},
		{name: "overflow", path: "/proc/self/fd/2147483648", want: false},
		{name: "negative", path: "/proc/self/fd/-1", want: false},
		{name: "regular-tar", path: "/tmp/upper.tar", want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsProcFDPath(tc.path); got != tc.want {
				t.Errorf("IsProcFDPath(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestContainerName(t *testing.T) {
	for _, tc := range []struct {
		name string
		spec specs.Spec
		want string
	}{
		{
			name: "no-name",
			spec: specs.Spec{},
			want: "",
		},
		{
			name: "container-name",
			spec: specs.Spec{
				Annotations: map[string]string{
					ContainerdContainerNameAnnotation: "cont",
				},
			},
			want: "cont",
		},
		{
			name: "remap",
			spec: specs.Spec{
				Annotations: map[string]string{
					ContainerdContainerNameAnnotation:  "cont-123",
					annotationContainerNameRemap + "1": "cont-123=cont",
				},
			},
			want: "cont",
		},
		{
			name: "remap-not-found",
			spec: specs.Spec{
				Annotations: map[string]string{
					ContainerdContainerNameAnnotation:  "cont",
					annotationContainerNameRemap + "1": "another-123=another",
				},
			},
			want: "cont",
		},
		{
			name: "remap-invalid",
			spec: specs.Spec{
				Annotations: map[string]string{
					ContainerdContainerNameAnnotation:  "cont",
					annotationContainerNameRemap + "1": "another-123",
				},
			},
			want: "cont",
		},
		{
			name: "remap-invalid-empty",
			spec: specs.Spec{
				Annotations: map[string]string{
					ContainerdContainerNameAnnotation:  "cont",
					annotationContainerNameRemap + "1": "",
				},
			},
			want: "cont",
		},
		{
			name: "remap-empty-name",
			spec: specs.Spec{
				Annotations: map[string]string{
					annotationContainerNameRemap + "1": "cont-123=cont",
				},
			},
			want: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ContainerName(&tc.spec)
			if got != tc.want {
				t.Errorf("ContainerName() got: %v, want: %v", got, tc.want)
			}
		})
	}
}

func TestTPUProxyEnabled(t *testing.T) {
	for _, tc := range []struct {
		name string
		spec specs.Spec
		conf config.Config
		want bool
	}{
		{
			name: "default-false",
			spec: specs.Spec{},
			conf: config.Config{},
			want: false,
		},
		{
			name: "config-true",
			spec: specs.Spec{},
			conf: config.Config{TPUProxy: true},
			want: true,
		},
		{
			name: "annotation-true",
			spec: specs.Spec{
				Annotations: map[string]string{
					AnnotationTPU: "true",
				},
			},
			conf: config.Config{},
			want: true,
		},
		{
			name: "device-accel-true",
			spec: specs.Spec{
				Linux: &specs.Linux{
					Devices: []specs.LinuxDevice{
						{Path: "/dev/accel0"},
					},
				},
			},
			conf: config.Config{},
			want: true,
		},
		{
			name: "device-vfio-group-true",
			spec: specs.Spec{
				Linux: &specs.Linux{
					Devices: []specs.LinuxDevice{
						{Path: "/dev/vfio/12"},
					},
				},
			},
			conf: config.Config{},
			want: true,
		},
		{
			name: "device-vfio-control-false",
			spec: specs.Spec{
				Linux: &specs.Linux{
					Devices: []specs.LinuxDevice{
						{Path: "/dev/vfio/vfio"},
					},
				},
			},
			conf: config.Config{},
			want: false,
		},
		{
			name: "device-other-false",
			spec: specs.Spec{
				Linux: &specs.Linux{
					Devices: []specs.LinuxDevice{
						{Path: "/dev/null"},
					},
				},
			},
			conf: config.Config{},
			want: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := TPUProxyEnabled(&tc.spec, &tc.conf)
			if got != tc.want {
				t.Errorf("TPUProxyEnabled() got: %v, want: %v", got, tc.want)
			}
		})
	}
}

// TestCopySpec checks that spec copies hold the given spec, and that the copy
// is actually sealed (i.e. read-only).
func TestCopySpec(t *testing.T) {
	want := &specs.Spec{
		Version:  "1.0.0",
		Hostname: "test",
		Process:  &specs.Process{Args: []string{"/bin/true"}},
	}
	f, err := CopySpec(want)
	if err != nil {
		t.Fatalf("CopySpec failed: %v", err)
	}
	defer f.Close()
	if _, err := f.WriteAt([]byte("{}"), 0); err == nil {
		t.Errorf("writing the spec copy succeeded")
	}
	data, err := io.ReadAll(io.NewSectionReader(f, 0, math.MaxInt64))
	if err != nil {
		t.Fatalf("error reading spec copy: %v", err)
	}
	var got specs.Spec
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("error decoding spec copy: %v", err)
	}
	if !reflect.DeepEqual(&got, want) {
		t.Errorf("spec copy got %+v, want %+v", got, want)
	}
}

// TestProcessIdentity checks that process identities tell processes apart, and
// that KillProcess doesn't kill a process with a different identity but the
// same PID.
func TestProcessIdentity(t *testing.T) {
	var procs [2]*exec.Cmd
	var identities [2]uint64
	for i := range procs {
		procs[i] = exec.Command("/bin/sleep", "1000")
		if err := procs[i].Start(); err != nil {
			t.Fatalf("cmd.Start() failed: %v", err)
		}
		defer procs[i].Process.Kill()
		var err error
		if identities[i], err = ProcessIdentity(procs[i].Process.Pid); err != nil {
			t.Fatalf("ProcessIdentity failed: %v", err)
		}
		if identities[i] == 0 {
			t.Skip("host has no pidfs")
		}
	}
	if identities[0] == identities[1] {
		t.Errorf("two processes have the same identity %d", identities[0])
	}
	pid := procs[0].Process.Pid
	pidfd, err := OpenProcess(pid, identities[0])
	if err != nil {
		t.Errorf("OpenProcess with the process identity failed: %v", err)
	} else {
		unix.Close(pidfd)
	}
	if _, err := OpenProcess(pid, identities[1]); err != unix.ESRCH {
		t.Errorf("OpenProcess with another process identity got %v, expected ESRCH", err)
	}
	if err := KillProcess(pid, identities[1]); err != nil {
		t.Errorf("KillProcess with another process identity failed: %v", err)
	}
	if err := procs[0].Process.Signal(unix.Signal(0)); err != nil {
		t.Errorf("KillProcess with another process identity killed the process: %v", err)
	}
	if err := KillProcess(pid, identities[0]); err != nil {
		t.Errorf("KillProcess failed: %v", err)
	}
	if err := procs[0].Wait(); err == nil {
		t.Errorf("process exited cleanly, expected it to be killed")
	}
}

func TestValidateSpecForContainerOOMScoreAdj(t *testing.T) {
	newSpec := func(oomScoreAdj *int, noNewPrivileges bool) *specs.Spec {
		return &specs.Spec{
			Process: &specs.Process{
				Args:            []string{"/bin/true"},
				Cwd:             "/",
				OOMScoreAdj:     oomScoreAdj,
				NoNewPrivileges: noNewPrivileges,
			},
		}
	}
	intPtr := func(i int) *int { return &i }

	for _, tc := range []struct {
		name     string
		old, new *specs.Spec
		wantErr  bool
	}{
		{name: "same", old: newSpec(intPtr(500), false), new: newSpec(intPtr(500), false)},
		{name: "changed", old: newSpec(intPtr(500), false), new: newSpec(intPtr(900), false)},
		{name: "added", old: newSpec(nil, false), new: newSpec(intPtr(900), false)},
		{name: "removed", old: newSpec(intPtr(500), false), new: newSpec(nil, false)},
		{
			// Other fields in specs.Process must still be validated.
			name:    "other field changed",
			old:     newSpec(intPtr(500), false),
			new:     newSpec(intPtr(900), true),
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSpecForContainer(tc.old, tc.new, "test")
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Errorf("validateSpecForContainer() = %v, wantErr: %t", err, tc.wantErr)
			}
		})
	}
}
