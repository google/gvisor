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

package nvconf

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/nvgpu"
)

func charDevice(major, minor uint32) unix.Stat_t {
	return unix.Stat_t{Mode: unix.S_IFCHR | 0600, Rdev: unix.Mkdev(major, minor)}
}

// lstatNVControlDevice reports dev/nvidiactl, if it exists, as the NVIDIA
// control device, since a test cannot create a device file. Nothing else is
// looked up.
func lstatNVControlDevice(path string, st *unix.Stat_t) error {
	if !strings.HasSuffix(path, "/dev/nvidiactl") {
		return fmt.Errorf("lstat of %q, want a path ending in /dev/nvidiactl", path)
	}
	// The control device exists only where the test made a file for it.
	if _, err := os.Lstat(path); err != nil {
		return err
	}
	*st = charDevice(nvgpu.NV_MAJOR_DEVICE_NUMBER, nvgpu.NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE)
	return nil
}

// makeRoot returns a dev root containing dev/nvidiactl if withCtl is true.
func makeRoot(t *testing.T, withCtl bool) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "dev"), 0755); err != nil {
		t.Fatal(err)
	}
	if withCtl {
		if err := os.WriteFile(filepath.Join(root, "dev/nvidiactl"), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// canonical returns path as an absolute path with symlinks resolved.
func canonical(t *testing.T, path string) string {
	t.Helper()
	abs, err := filepath.Abs(path)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

func TestParseDevRoots(t *testing.T) {
	for _, tc := range []struct {
		name    string
		roots   string
		want    []string
		wantErr string
	}{
		{name: "single", roots: "/run/nvidia/driver", want: []string{"/run/nvidia/driver"}},
		{name: "list", roots: "/,/run/nvidia/driver", want: []string{"/", "/run/nvidia/driver"}},
		{name: "default", roots: DefaultDevRoots, want: []string{"/", "/run/nvidia/driver"}},
		{name: "empty", roots: "", wantErr: "dev root must not be empty"},
		{name: "empty entry", roots: "/,", wantErr: "dev root must not be empty"},
		{name: "relative", roots: "/,run/nvidia/driver", wantErr: `dev root "run/nvidia/driver" must be an absolute path`},
		{name: "dot", roots: ".", wantErr: `dev root "." must be an absolute path`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseDevRoots(tc.roots)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("ParseDevRoots(%q) error = %v, want it to contain %q", tc.roots, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseDevRoots(%q) failed: %v", tc.roots, err)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("ParseDevRoots(%q) = %q, want %q", tc.roots, got, tc.want)
			}
		})
	}
}

func TestResolveDevRootSingleRoot(t *testing.T) {
	// A single root is checked like any other.
	const missing = "/nonexistent/forced/root"
	if root, err := resolveDevRoot(missing, lstatNVControlDevice); err == nil {
		t.Errorf("resolveDevRoot(%q) = %q, want error", missing, root)
	} else if !strings.Contains(err.Error(), "/nonexistent") {
		t.Errorf("resolveDevRoot(%q) error %q does not name the path it tried", missing, err)
	}

	valid := makeRoot(t, true)
	got, err := resolveDevRoot(valid, lstatNVControlDevice)
	if err != nil {
		t.Fatalf("resolveDevRoot(%q) failed: %v", valid, err)
	}
	if want := canonical(t, valid); got != want {
		t.Errorf("resolveDevRoot(%q) = %q, want %q", valid, got, want)
	}
}

func TestResolveDevRootInvalid(t *testing.T) {
	for _, roots := range []string{"", "relative/root"} {
		if root, err := ResolveDevRoot(roots); err == nil {
			t.Errorf("ResolveDevRoot(%q) = %q, want error", roots, root)
		}
	}
}

func TestResolveDevRootNotFound(t *testing.T) {
	first := makeRoot(t, false)
	second := makeRoot(t, false)
	_, err := resolveDevRoot(first+","+second, lstatNVControlDevice)
	if err == nil {
		t.Fatal("resolveDevRoot succeeded, want error")
	}
	for _, want := range []string{filepath.Join(canonical(t, first), "dev/nvidiactl"), filepath.Join(canonical(t, second), "dev/nvidiactl"), "no such file or directory"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("resolveDevRoot error %q does not contain %q", err, want)
		}
	}
}

func TestResolveDevRootOrder(t *testing.T) {
	missing := makeRoot(t, false)
	first := makeRoot(t, true)
	second := makeRoot(t, true)
	for _, tc := range []struct {
		name  string
		roots []string
		want  string
	}{
		{name: "first valid wins", roots: []string{first, second}, want: first},
		{name: "skips missing", roots: []string{missing, second}, want: second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			commaSeparatedRoots := strings.Join(tc.roots, ",")
			got, err := resolveDevRoot(commaSeparatedRoots, lstatNVControlDevice)
			if err != nil {
				t.Fatalf("resolveDevRoot(%q) failed: %v", commaSeparatedRoots, err)
			}
			if want := canonical(t, tc.want); got != want {
				t.Errorf("resolveDevRoot(%q) = %q, want %q", commaSeparatedRoots, got, want)
			}
		})
	}
}

func TestResolveDevRootSymlink(t *testing.T) {
	real := makeRoot(t, true)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	got, err := resolveDevRoot(link, lstatNVControlDevice)
	if err != nil {
		t.Fatalf("resolveDevRoot(%q) failed: %v", link, err)
	}
	if want := canonical(t, real); got != want {
		t.Errorf("resolveDevRoot(%q) = %q, want the symlink resolved to %q", link, got, want)
	}
}

func TestCheckNVControlDevice(t *testing.T) {
	statAs := func(st unix.Stat_t) func(string, *unix.Stat_t) error {
		return func(_ string, got *unix.Stat_t) error {
			*got = st
			return nil
		}
	}

	regular := makeRoot(t, true)

	// A symlink at dev/nvidiactl, even to the real control device.
	linked := makeRoot(t, false)
	if err := os.Symlink(filepath.Join(regular, "dev/nvidiactl"), filepath.Join(linked, "dev/nvidiactl")); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name    string
		devRoot string
		lstat   func(string, *unix.Stat_t) error
		wantErr string
	}{
		{name: "control device", devRoot: "/", lstat: statAs(charDevice(nvgpu.NV_MAJOR_DEVICE_NUMBER, nvgpu.NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE))},
		{name: "other minor", devRoot: "/", lstat: statAs(charDevice(nvgpu.NV_MAJOR_DEVICE_NUMBER, 0)), wantErr: "is device 195:0, want 195:255"},
		{name: "other major", devRoot: "/", lstat: statAs(charDevice(1, nvgpu.NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE)), wantErr: "is device 1:255, want 195:255"},
		{name: "regular file", devRoot: regular, lstat: unix.Lstat, wantErr: "not a character device"},
		{name: "symlink", devRoot: linked, lstat: unix.Lstat, wantErr: "not a character device"},
		{name: "missing", devRoot: makeRoot(t, false), lstat: unix.Lstat, wantErr: "no such file or directory"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkNVControlDevice(tc.devRoot, tc.lstat)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("checkNVControlDevice(%q) failed: %v", tc.devRoot, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("checkNVControlDevice(%q) error = %v, want it to contain %q", tc.devRoot, err, tc.wantErr)
			}
		})
	}
}

func TestHostDriverVersionRejectsOtherFiles(t *testing.T) {
	// A regular file at dev/nvidiactl is not the control device, so it must be
	// rejected before anything is sent to it.
	root := makeRoot(t, true)
	if version, err := HostDriverVersion(root); err == nil {
		t.Errorf("HostDriverVersion(%q) = %q, want error", root, version)
	} else if want := "not a character device"; !strings.Contains(err.Error(), want) {
		t.Errorf("HostDriverVersion(%q) error %q does not contain %q", root, err, want)
	}
}
