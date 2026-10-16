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

package sandbox

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/runsc/cgroup"
	"gvisor.dev/gvisor/runsc/specutils"
)

func TestIsRunning(t *testing.T) {
	var s Sandbox
	// Pid == 0 should not be running.
	running, err := s.IsRunning()
	if err != nil {
		t.Fatalf("IsRunning() error = %v, want nil", err)
	}
	if running {
		t.Errorf("IsRunning() = true for pid 0, want false")
	}

	// Current process should be running.
	s.Pid.Store(os.Getpid())
	running, err = s.IsRunning()
	if err != nil {
		t.Fatalf("IsRunning() error = %v, want nil", err)
	}
	if !running {
		t.Errorf("IsRunning() = false for current process, want true")
	}

	// Spawn a child process that exits immediately and becomes a zombie until reaped.
	cmd := exec.Command("/bin/true")
	if err := cmd.Start(); err != nil {
		t.Fatalf("cmd.Start() failed: %v", err)
	}
	childPid := cmd.Process.Pid
	s.Pid.Store(childPid)

	// Wait until child enters zombie state ('Z').
	deadline := time.Now().Add(5 * time.Second)
	for {
		statBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", childPid))
		if err == nil && strings.Contains(string(statBytes), ") Z ") {
			break
		}
		if time.Now().After(deadline) {
			_ = cmd.Wait()
			t.Fatalf("timed out waiting for child pid %d to become zombie", childPid)
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Zombie process must NOT be reported as running.
	running, err = s.IsRunning()
	if err != nil {
		_ = cmd.Wait()
		t.Fatalf("IsRunning() on zombie error = %v, want nil", err)
	}
	if running {
		t.Errorf("IsRunning() = true for zombie process %d, want false", childPid)
	}

	// Reap the zombie process.
	_ = cmd.Wait()
	running, err = s.IsRunning()
	if err != nil {
		t.Fatalf("IsRunning() on reaped process error = %v, want nil", err)
	}
	if running {
		t.Errorf("IsRunning() = true for reaped process %d, want false", childPid)
	}
}

func TestGetGCSURIFromImagePath(t *testing.T) {
	tmpDir := t.TempDir()

	testCases := []struct {
		name      string
		content   string
		writeOpts bool
		want      string
	}{
		{
			name:      "missing file",
			writeOpts: false,
			want:      "",
		},
		{
			name:      "invalid json",
			content:   "not valid json",
			writeOpts: true,
			want:      "",
		},
		{
			name:      "empty bucket",
			content:   `{"bucket": ""}`,
			writeOpts: true,
			want:      "",
		},
		{
			name:      "bucket only",
			content:   `{"bucket": "my-test-bucket"}`,
			writeOpts: true,
			want:      "gs://my-test-bucket",
		},
		{
			name:      "bucket with object prefix",
			content:   `{"bucket": "my-test-bucket", "object_prefix": "snapshots/test/"}`,
			writeOpts: true,
			want:      "gs://my-test-bucket/snapshots/test/",
		},
		{
			name:      "bucket with leading slash in object prefix",
			content:   `{"bucket": "my-test-bucket", "object_prefix": "/snapshots/test/"}`,
			writeOpts: true,
			want:      "gs://my-test-bucket/snapshots/test/",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			subDir := filepath.Join(tmpDir, tc.name)
			if err := os.MkdirAll(subDir, 0755); err != nil {
				t.Fatalf("failed to create directory: %v", err)
			}
			if tc.writeOpts {
				optsPath := filepath.Join(subDir, checkpointGCSOptsFileName)
				if err := os.WriteFile(optsPath, []byte(tc.content), 0644); err != nil {
					t.Fatalf("failed to write %s: %v", optsPath, err)
				}
			}
			got := getGCSURIFromImagePath(subDir)
			if got != tc.want {
				t.Errorf("getGCSURIFromImagePath(%q) = %q, want %q", subDir, got, tc.want)
			}
		})
	}
}

type fakeCgroup struct {
	cgroup.Cgroup
	numCPU    int
	numCPUErr error
	cpuQuota  int64
	cpuPeriod int64
}

func (f *fakeCgroup) NumCPU() (int, error) {
	return f.numCPU, f.numCPUErr
}

func (f *fakeCgroup) CPUQuota() (int64, error) {
	return f.cpuQuota, nil
}

func (f *fakeCgroup) CPUPeriod() (int64, error) {
	return f.cpuPeriod, nil
}

func TestCalculateCPUNum(t *testing.T) {
	for _, tc := range []struct {
		name            string
		numCPU          int
		numCPUErr       error
		cpuQuota        int64
		cpuPeriod       int64
		cpuNumFromQuota bool
		want            int
	}{
		{
			name:      "cgroup NumCPU error fallback to runtime.NumCPU",
			numCPUErr: errors.New("cgroup cpuset read error"),
			want:      runtime.NumCPU(),
		},
		{
			name:   "cgroup NumCPU success",
			numCPU: 8,
			want:   8,
		},
		{
			name:            "cgroup NumCPU error fallback with quota limit",
			numCPUErr:       errors.New("cgroup cpuset read error"),
			cpuQuota:        400000,
			cpuPeriod:       100000,
			cpuNumFromQuota: true,
			want:            min(runtime.NumCPU(), 4),
		},
		{
			name:            "cgroup NumCPU error fallback with low quota minCPUs floor",
			numCPUErr:       errors.New("cgroup cpuset read error"),
			cpuQuota:        100000,
			cpuPeriod:       100000,
			cpuNumFromQuota: true,
			want:            min(runtime.NumCPU(), 2),
		},
		{
			name:            "cgroup NumCPU success with quota limit",
			numCPU:          16,
			cpuQuota:        400000,
			cpuPeriod:       100000,
			cpuNumFromQuota: true,
			want:            4,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cg := &fakeCgroup{
				numCPU:    tc.numCPU,
				numCPUErr: tc.numCPUErr,
				cpuQuota:  tc.cpuQuota,
				cpuPeriod: tc.cpuPeriod,
			}
			gotNum, gotQuota, gotPeriod, err := calculateCPUNum(cg, tc.cpuNumFromQuota)
			if err != nil {
				t.Fatalf("calculateCPUNum failed: %v", err)
			}
			if gotNum != tc.want {
				t.Errorf("calculateCPUNum() got cpuNum = %d, want %d", gotNum, tc.want)
			}
			if gotQuota != tc.cpuQuota {
				t.Errorf("calculateCPUNum() got cpuQuota = %d, want %d", gotQuota, tc.cpuQuota)
			}
			if gotPeriod != tc.cpuPeriod {
				t.Errorf("calculateCPUNum() got cpuPeriod = %d, want %d", gotPeriod, tc.cpuPeriod)
			}
		})
	}
}

func TestRootfsUpperTarFlags(t *testing.T) {
	tmpDir := t.TempDir()
	targetPath := filepath.Join(tmpDir, "target.tar")
	if err := os.WriteFile(targetPath, []byte("tar-data"), 0644); err != nil {
		t.Fatalf("os.WriteFile(%q) failed: %v", targetPath, err)
	}
	symlinkPath := filepath.Join(tmpDir, "symlink.tar")
	if err := os.Symlink(targetPath, symlinkPath); err != nil {
		t.Fatalf("os.Symlink(%q, %q) failed: %v", targetPath, symlinkPath, err)
	}

	if f, err := os.OpenFile(symlinkPath, rootfsUpperTarFlags(symlinkPath), 0644); err == nil {
		f.Close()
		t.Fatalf("os.OpenFile(%q, rootfsUpperTarFlags) error = nil, want %v", symlinkPath, unix.ELOOP)
	} else if !errors.Is(err, unix.ELOOP) {
		t.Errorf("os.OpenFile(%q, rootfsUpperTarFlags) error = %v, want %v", symlinkPath, err, unix.ELOOP)
	}

	f, err := os.OpenFile(targetPath, rootfsUpperTarFlags(targetPath), 0644)
	if err != nil {
		t.Fatalf("os.OpenFile(%q, rootfsUpperTarFlags) error = %v, want nil", targetPath, err)
	}
	defer f.Close()

	procFDPath := fmt.Sprintf("/proc/self/fd/%d", f.Fd())
	dupFile, err := os.OpenFile(procFDPath, rootfsUpperTarFlags(procFDPath), 0644)
	if err != nil {
		t.Fatalf("os.OpenFile(%q, rootfsUpperTarFlags) error = %v, want nil", procFDPath, err)
	}
	dupFile.Close()

	for _, tc := range []struct {
		path string
		want bool
	}{
		{path: "/proc/self/fd/3", want: true},
		{path: "/proc/thread-self/fd/4", want: true},
		{path: "/dev/fd/5", want: true},
		{path: "/proc/self/fd/", want: false},
		{path: "/proc/self/fd/../etc/passwd", want: false},
		{path: "/proc/self/fd/2147483648", want: false},
		{path: "/tmp/upper.tar", want: false},
	} {
		if got := specutils.IsProcFDPath(tc.path); got != tc.want {
			t.Errorf("specutils.IsProcFDPath(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestOpenReadOnlyTree(t *testing.T) {
	dir := t.TempDir()
	const name = "file"
	if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0666); err != nil {
		t.Fatalf("os.WriteFile failed: %v", err)
	}
	treeFD, err := openReadOnlyTree(dir)
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.ENOSYS) {
		t.Skipf("openReadOnlyTree needs CAP_SYS_ADMIN and Linux 5.12: %v", err)
	}
	if err != nil {
		t.Fatalf("openReadOnlyTree failed: %v", err)
	}
	defer unix.Close(treeFD)
	f, err := openCheckpointFile(treeFD, dir, name, unix.O_RDONLY)
	if err != nil {
		t.Fatalf("open through the read-only tree failed: %v", err)
	}
	defer f.Close()
	fd := int(f.Fd())

	// A symlink leading out of the directory is not followed.
	if err := os.Symlink(filepath.Join("..", filepath.Base(dir), name), filepath.Join(dir, "escape")); err != nil {
		t.Fatalf("os.Symlink failed: %v", err)
	}
	if ef, err := openCheckpointFile(treeFD, dir, "escape", unix.O_RDONLY); err == nil {
		ef.Close()
		t.Errorf("open through a symlink leaving the directory succeeded, want EXDEV")
	} else if !errors.Is(err, unix.EXDEV) {
		t.Errorf("open through a symlink leaving the directory failed with %v, want EXDEV", err)
	}

	// The file can not be reopened for writing through any path.
	for _, flags := range []int{unix.O_WRONLY, unix.O_RDWR} {
		wfd, err := unix.Open(fmt.Sprintf("/proc/self/fd/%d", fd), flags|unix.O_CLOEXEC, 0)
		if err == nil {
			unix.Close(wfd)
			t.Errorf("reopening with flags %#x succeeded, want EROFS", flags)
		} else if !errors.Is(err, unix.EROFS) {
			t.Errorf("reopening with flags %#x failed with %v, want EROFS", flags, err)
		}
	}
	// The directory itself is unaffected.
	if err := os.WriteFile(filepath.Join(dir, name), []byte("y"), 0666); err != nil {
		t.Errorf("writing through the original path failed: %v", err)
	}
}

func TestOpenFSRestoreFilesForLocalCheckpointErrors(t *testing.T) {
	dir := t.TempDir()
	files, err := createFSCheckpointLocalFiles(dir, "rootfs", false)
	if err != nil {
		t.Fatalf("createFSCheckpointLocalFiles(%q, \"rootfs\") failed: %v", dir, err)
	}
	for _, f := range files {
		_ = f.Close()
	}

	for _, tc := range []struct {
		name    string
		paths   []string
		wantErr string
	}{
		{name: "duplicate explicit prefix path", paths: []string{filepath.Join(dir, "rootfs"), filepath.Join(dir, "rootfs")}, wantErr: "duplicate filesystem checkpoint bundle"},
		{name: "duplicate mixing directory and explicit prefix", paths: []string{dir, filepath.Join(dir, "rootfs")}, wantErr: "duplicate filesystem checkpoint bundle"},
		{name: "non-existent directory with trailing slash", paths: []string{filepath.Join(dir, "missing") + "/"}, wantErr: "does not exist"},
		{name: "empty directory", paths: []string{t.TempDir(), dir}, wantErr: "opening manifest file"},
		{name: "only empty strings", paths: []string{"", ""}, wantErr: "empty --fs-restore-image-path"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := openFSRestoreFilesForLocalCheckpoint(tc.paths, false); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("openFSRestoreFilesForLocalCheckpoint(%q) error = %v, want substring %q", tc.paths, err, tc.wantErr)
			}
		})
	}
}

func TestDiscoverFSCheckpointPrefixesFollowsSymlink(t *testing.T) {
	dir := t.TempDir()
	files, err := createFSCheckpointLocalFiles(dir, "fs", false)
	if err != nil {
		t.Fatalf("createFSCheckpointLocalFiles(%q, \"fs\") failed: %v", dir, err)
	}
	for _, f := range files {
		_ = f.Close()
	}
	link := filepath.Join(t.TempDir(), "latest")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatalf("os.Symlink(%q, %q) failed: %v", dir, link, err)
	}

	got, err := discoverFSCheckpointPrefixes(link)
	if err != nil {
		t.Fatalf("discoverFSCheckpointPrefixes(%q) failed: %v", link, err)
	}
	if want := []string{"fs"}; !slices.Equal(got, want) {
		t.Errorf("discoverFSCheckpointPrefixes(%q) = %q, want %q", link, got, want)
	}
}

func TestIsGCSRestorePath(t *testing.T) {
	gcsDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(gcsDir, checkpointGCSOptsFileName), []byte("{}"), 0644); err != nil {
		t.Fatalf("os.WriteFile failed: %v", err)
	}
	localDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(localDir, "bundles"), 0755); err != nil {
		t.Fatalf("os.Mkdir failed: %v", err)
	}

	for _, tc := range []struct {
		name         string
		path         string
		wantGCS      bool
		wantPrefixed bool
	}{
		{name: "gcs directory", path: gcsDir, wantGCS: true},
		{name: "gcs prefix", path: filepath.Join(gcsDir, "fs"), wantGCS: true, wantPrefixed: true},
		{name: "gcs nested prefix", path: filepath.Join(gcsDir, "bundles", "fs"), wantGCS: true, wantPrefixed: true},
		{name: "gcs nested directory prefix", path: filepath.Join(gcsDir, "a", "b") + "/", wantGCS: true, wantPrefixed: true},
		{name: "local directory", path: localDir},
		{name: "local nested prefix", path: filepath.Join(localDir, "bundles", "fs"), wantPrefixed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gotGCS, gotPrefixed := isGCSRestorePath(tc.path)
			if gotGCS != tc.wantGCS || gotPrefixed != tc.wantPrefixed {
				t.Errorf("isGCSRestorePath(%q) = (%t, %t), want (%t, %t)", tc.path, gotGCS, gotPrefixed, tc.wantGCS, tc.wantPrefixed)
			}
		})
	}
}
