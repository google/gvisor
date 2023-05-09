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
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
)

func getParentPID(childPID int) (int, error) {
	cmd := fmt.Sprintf("grep PPid: %s | sed 's/PPid:\\s//'", procPath(strconv.Itoa(childPID), "status"))
	parent, err := exec.Command("bash", "-c", cmd).CombinedOutput()
	if err != nil {
		return -1, fmt.Errorf("failed to fetch parent PID of %d: %v, out:\n%s", childPID, err, string(parent))
	}
	parentPID, err := strconv.Atoi(strings.TrimSpace(string(parent)))
	if err != nil {
		return -1, fmt.Errorf("failed to parse PPID %q: %v", string(parent), err)
	}
	return parentPID, nil
}

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
	procRoot := procPath(strconv.Itoa(pid), "root")
	chroot, err := filepath.EvalSymlinks(procRoot)
	if err != nil {
		t.Fatalf("error resolving /proc/<pid>/root symlink: %v", err)
	}
	if chroot != "/" {
		t.Errorf("sandbox is not chroot'd, it should be inside: /, got: %q", chroot)
	}

	path, err := filepath.EvalSymlinks(procPath(strconv.Itoa(pid), "cwd"))
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
	if want, got := 2, len(fi); want != got {
		t.Fatalf("chroot dir got %d entries, want %d", got, want)
	}

	// chroot dir is prepared by runsc and should contains only /etc and /proc.
	for i, want := range []string{"etc", "proc"} {
		if got := fi[i].Name(); got != want {
			t.Errorf("chroot got child %v, want %v", got, want)
		}
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
	parentPID, err := getParentPID(sandPID)
	if err != nil {
		t.Fatalf("failed to fetch runsc parent PID: %v", err)
	}

	// Get all children from parent.
	var childrenPIDs []int
	procfsRoot := procPath()
	procDirs, err := os.ReadDir(procfsRoot)
	if err != nil {
		t.Fatalf("cannot list processes in %s: %s", procfsRoot, err)
	}
	for _, procDir := range procDirs {
		if !procDir.IsDir() {
			continue
		}
		procPID, err := strconv.Atoi(procDir.Name())
		if err != nil {
			// We only care about directories that are PIDs.
			continue
		}
		// Now check if it is a child of parentPID.
		parent, err := getParentPID(procPID)
		if err != nil {
			// Skip, this may be a race condition with a process that has since gone away.
			t.Logf("Non-fatal warning: cannot get parent PID of %d (process likely gone): %v", procPID, err)
			continue
		}
		if parent == parentPID {
			t.Logf("runsc parent PID %d has child PID %d", parentPID, procPID)
			childrenPIDs = append(childrenPIDs, procPID)
		}
	}
	// Ensure we have seen at least one child PID.
	if len(childrenPIDs) == 0 {
		t.Fatalf("Found no children of runsc parent PID %d", parentPID)
	}

	// This where the root directory is mapped on the host and that's where the
	// gofer must have chroot'd to.
	root := "/root"

	for _, childPID := range childrenPIDs {
		if childPID == sandPID {
			// Skip the sandbox, all other immediate children are gofers.
			continue
		}

		// Check that gofer is chroot'ed.
		chroot, err := filepath.EvalSymlinks(procPath(strconv.Itoa(childPID), "root"))
		if err != nil {
			t.Fatalf("error resolving /proc/<pid>/root symlink: %v", err)
		}
		if root != chroot {
			t.Errorf("gofer chroot is wrong, want: %q, got: %q", root, chroot)
		}

		path, err := filepath.EvalSymlinks(procPath(strconv.Itoa(childPID), "cwd"))
		if err != nil {
			t.Fatalf("error resolving /proc/<pid>/cwd symlink: %v", err)
		}
		if root != path {
			t.Errorf("gofer current dir is wrong, want: %q, got: %q", root, path)
		}
	}
}
