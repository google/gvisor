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

package linux

import (
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/host"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/testutil"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// TestFDsToHostFilesClosesRemainingFDs verifies that when a host FD can't be
// imported, the FDs after it are closed rather than leaked.
func TestFDsToHostFilesClosesRemainingFDs(t *testing.T) {
	k, err := testutil.Boot()
	if err != nil {
		t.Fatalf("Boot failed: %v", err)
	}
	ctx := k.SupervisorContext()
	hostFS, err := host.NewFilesystem(k.VFS())
	if err != nil {
		t.Fatalf("host.NewFilesystem failed: %v", err)
	}
	defer hostFS.DecRef(ctx)
	k.SetHostMount(k.VFS().NewDisconnectedMount(hostFS, nil, &vfs.MountOptions{}))

	// Directories can't be imported. host.NewFD closes dir when it fails.
	dir, err := unix.Open(t.TempDir(), unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	// peer reads EOF once sock is closed.
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("Socketpair failed: %v", err)
	}
	sock, peer := fds[0], fds[1]
	defer unix.Close(peer)

	files, trunc := fdsToHostFiles(ctx, []int{dir, sock})
	for _, f := range files {
		f.DecRef(ctx)
	}
	if len(files) != 0 || !trunc {
		t.Errorf("fdsToHostFiles = (%d files, %t), want (0 files, true)", len(files), trunc)
	}

	if err := unix.SetNonblock(peer, true); err != nil {
		t.Fatalf("SetNonblock failed: %v", err)
	}
	if n, err := unix.Read(peer, make([]byte, 1)); n != 0 || err != nil {
		t.Errorf("Read from peer = (%d, %v), want EOF: FD %d after the failed import was not closed", n, err, sock)
	}
}
