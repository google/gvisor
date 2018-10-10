// Copyright 2018 Google Inc.
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

// Package root is used for tests that requires sysadmin privileges run. First,
// follow the setup instruction in runsc/test/README.md. To run these test:
//
//     bazel build //runsc/test/root:root_test
//     root_test=$(find -L ./bazel-bin/ -executable -type f -name root_test | grep __main__)
//     sudo RUNSC_RUNTIME=runsc-test ${root_test}
package root

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/syndtr/gocapability/capability"
	"gvisor.googlesource.com/gvisor/runsc/specutils"
	"gvisor.googlesource.com/gvisor/runsc/test/testutil"
)

// TestChroot verifies that the sandbox is chroot'd and that mounts are cleaned
// up after the sandbox is destroyed.
func TestChroot(t *testing.T) {
	d := testutil.MakeDocker("chroot-test")
	if err := d.Run("alpine", "sleep", "10000"); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
	defer d.CleanUp()

	pid, err := d.SandboxPid()
	if err != nil {
		t.Fatalf("Docker.SandboxPid(): %v", err)
	}

	// Check that sandbox is chroot'ed.
	chroot, err := filepath.EvalSymlinks(filepath.Join("/proc", strconv.Itoa(pid), "root"))
	if err != nil {
		t.Fatalf("error resolving /proc/<pid>/root symlink: %v", err)
	}
	if want := "/tmp/runsc-sandbox-chroot-"; !strings.HasPrefix(chroot, want) {
		t.Errorf("sandbox is not chroot'd, it should be inside: %q, got: %q", want, chroot)
	}

	path, err := filepath.EvalSymlinks(filepath.Join("/proc", strconv.Itoa(pid), "cwd"))
	if err != nil {
		t.Fatalf("error resolving /proc/<pid>/cwd symlink: %v", err)
	}
	if chroot != path {
		t.Errorf("sandbox current dir is wrong, want: %q, got: %q", chroot, path)
	}

	fi, err := ioutil.ReadDir(chroot)
	if err != nil {
		t.Fatalf("error listing %q: %v", chroot, err)
	}
	if want, got := 2, len(fi); want != got {
		t.Fatalf("chroot dir got %d entries, want %d", want, got)
	}

	// chroot dir is prepared by runsc and should contains only the executable
	// and /proc.
	files := []string{fi[0].Name(), fi[1].Name()}
	sort.Strings(files)
	if want := []string{"proc", "runsc"}; !reflect.DeepEqual(files, want) {
		t.Errorf("chroot got children %v, want %v", files, want)
	}

	d.CleanUp()

	// Check that chroot directory was cleaned up.
	if _, err := os.Stat(chroot); err == nil || !os.IsNotExist(err) {
		t.Errorf("chroot directory %q was not deleted: %v", chroot, err)
	}
}

func TestChrootGofer(t *testing.T) {
	d := testutil.MakeDocker("chroot-test")
	if err := d.Run("alpine", "sleep", "10000"); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
	defer d.CleanUp()

	// It's tricky to find gofers. Get sandbox PID first, then find parent. From
	// parent get all immediate children, remove the sandbox, and everything else
	// are gofers.
	sandPID, err := d.SandboxPid()
	if err != nil {
		t.Fatalf("Docker.SandboxPid(): %v", err)
	}

	// Find sandbox's parent PID.
	cmd := fmt.Sprintf("grep PPid /proc/%d/status | awk '{print $2}'", sandPID)
	parent, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	if err != nil {
		t.Fatalf("failed to fetch runsc (%d) parent PID: %v, out:\n%s", sandPID, err, string(parent))
	}
	parentPID, err := strconv.Atoi(strings.TrimSpace(string(parent)))
	if err != nil {
		t.Fatalf("failed to parse PPID %q: %v", string(parent), err)
	}

	// Get all children from parent.
	childrenOut, err := exec.Command("/usr/bin/pgrep", "-P", strconv.Itoa(parentPID)).CombinedOutput()
	if err != nil {
		t.Fatalf("failed to fetch containerd-shim children: %v", err)
	}
	children := strings.Split(strings.TrimSpace(string(childrenOut)), "\n")

	// This where the root directory is mapped on the host and that's where the
	// gofer must have chroot'd to.
	root, err := d.RootDirInHost()
	if err != nil {
		t.Fatalf("Docker.RootDirInHost(): %v", err)
	}

	for _, child := range children {
		childPID, err := strconv.Atoi(child)
		if err != nil {
			t.Fatalf("failed to parse child PID %q: %v", child, err)
		}
		if childPID == sandPID {
			// Skip the sandbox, all other immediate children are gofers.
			continue
		}

		// Check that gofer is chroot'ed.
		chroot, err := filepath.EvalSymlinks(filepath.Join("/proc", child, "root"))
		if err != nil {
			t.Fatalf("error resolving /proc/<pid>/root symlink: %v", err)
		}
		if root != chroot {
			t.Errorf("gofer chroot is wrong, want: %q, got: %q", root, chroot)
		}

		path, err := filepath.EvalSymlinks(filepath.Join("/proc", child, "cwd"))
		if err != nil {
			t.Fatalf("error resolving /proc/<pid>/cwd symlink: %v", err)
		}
		if root != path {
			t.Errorf("gofer current dir is wrong, want: %q, got: %q", root, path)
		}
	}
}

func TestMain(m *testing.M) {
	testutil.EnsureSupportedDockerVersion()

	if !specutils.HasCapabilities(capability.CAP_SYS_ADMIN, capability.CAP_DAC_OVERRIDE) {
		fmt.Println("Test requires sysadmin privileges to run. Try again with sudo.")
		os.Exit(1)
	}

	os.Exit(m.Run())
}
