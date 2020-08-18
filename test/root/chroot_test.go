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

// Package root is used for tests that requires sysadmin privileges run.
package root

import (
	"context"
	"fmt"
	"io/ioutil"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
)

// TestChroot verifies that the sandbox is chroot'd and that mounts are cleaned
// up after the sandbox is destroyed.
func TestChroot(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	if err := d.Spawn(ctx, dockerutil.RunOpts{
		Image: "basic/alpine",
	}, "sleep", "10000"); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	pid, err := d.SandboxPid(ctx)
	if err != nil {
		t.Fatalf("Docker.SandboxPid(): %v", err)
	}

	// Check that sandbox is chroot'ed.
	procRoot := filepath.Join("/proc", strconv.Itoa(pid), "root")
	chroot, err := filepath.EvalSymlinks(procRoot)
	if err != nil {
		t.Fatalf("error resolving /proc/<pid>/root symlink: %v", err)
	}
	if chroot != "/" {
		t.Errorf("sandbox is not chroot'd, it should be inside: /, got: %q", chroot)
	}

	path, err := filepath.EvalSymlinks(filepath.Join("/proc", strconv.Itoa(pid), "cwd"))
	if err != nil {
		t.Fatalf("error resolving /proc/<pid>/cwd symlink: %v", err)
	}
	if chroot != path {
		t.Errorf("sandbox current dir is wrong, want: %q, got: %q", chroot, path)
	}

	fi, err := ioutil.ReadDir(procRoot)
	if err != nil {
		t.Fatalf("error listing %q: %v", chroot, err)
	}
	if want, got := 1, len(fi); want != got {
		t.Fatalf("chroot dir got %d entries, want %d", got, want)
	}

	// chroot dir is prepared by runsc and should contains only /proc.
	if fi[0].Name() != "proc" {
		t.Errorf("chroot got children %v, want %v", fi[0].Name(), "proc")
	}

	d.CleanUp(ctx)
}

func TestChrootGofer(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	if err := d.Spawn(ctx, dockerutil.RunOpts{
		Image: "basic/alpine",
	}, "sleep", "10000"); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	// It's tricky to find gofers. Get sandbox PID first, then find parent. From
	// parent get all immediate children, remove the sandbox, and everything else
	// are gofers.
	sandPID, err := d.SandboxPid(ctx)
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
	root := "/root"

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
