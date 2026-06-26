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

package fusehost

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/test/testutil"
)

const guestFD = 101

func TestFuseHostPassthrough(t *testing.T) {
	runscPath, err := testutil.FindFile("runsc/runsc")
	if err != nil {
		t.Fatalf("FindFile(runsc): %v", err)
	}
	workloadPath, err := testutil.FindFile("test/fuse_host/workload/workload")
	if err != nil {
		t.Fatalf("FindFile(workload): %v", err)
	}

	// Create backing directory with test data.
	backDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(backDir, "testfile"), []byte("hello from the host FUSE server\n"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Create socketpair for FUSE communication.
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("Socketpair: %v", err)
	}
	sandboxFile := os.NewFile(uintptr(fds[0]), "fuse-sandbox")
	defer sandboxFile.Close()
	serverFD := fds[1]
	defer unix.Close(serverFD)

	// Start the FUSE server.
	go Serve(serverFD, backDir)

	// Set up OCI bundle with a writable /tmp for the FUSE mount point.
	spec := testutil.NewSpecWithArgs(workloadPath, fmt.Sprintf("--fd=%d", guestFD))
	spec.Mounts = append(spec.Mounts, specs.Mount{
		Type:        "tmpfs",
		Destination: "/tmp",
	})
	bundleDir, cleanupBundle, err := testutil.SetupBundleDir(spec)
	if err != nil {
		t.Fatalf("SetupBundleDir: %v", err)
	}
	defer cleanupBundle()

	rootDir, cleanupRoot, err := testutil.SetupRootDir()
	if err != nil {
		t.Fatalf("SetupRootDir: %v", err)
	}
	defer cleanupRoot()

	id := testutil.RandomContainerID()

	// Build runsc command.
	cmd := exec.Command(runscPath,
		"--root="+rootDir,
		"--rootless",
		"--TESTONLY-unsafe-nonroot",
		"--network=none",
		"run",
		fmt.Sprintf("--pass-fd=3:%d", guestFD),
		"--bundle="+bundleDir,
		id,
	)
	cmd.ExtraFiles = []*os.File{sandboxFile}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &unix.SysProcAttr{
		Cloneflags: unix.CLONE_NEWUSER | unix.CLONE_NEWNS,
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getuid(), Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getgid(), Size: 1},
		},
		GidMappingsEnableSetgroups: false,
		Credential: &syscall.Credential{
			Uid: 0,
			Gid: 0,
		},
	}

	if err := cmd.Run(); err != nil {
		t.Fatalf("runsc run: %v", err)
	}
}
