// Copyright 2020 The gVisor Authors.
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

package fuse

import (
	"fmt"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/testutil"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

func setup(t *testing.T) *testutil.System {
	k, err := testutil.Boot()
	if err != nil {
		t.Fatalf("Error creating kernel: %v", err)
	}

	ctx := k.SupervisorContext()
	creds := auth.CredentialsFromContext(ctx)

	k.VFS().MustRegisterFilesystemType(Name, &FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserList:  true,
		AllowUserMount: true,
	})

	mntns, err := k.VFS().NewMountNamespace(ctx, creds, "", "tmpfs", &vfs.MountOptions{})
	if err != nil {
		t.Fatalf("NewMountNamespace(): %v", err)
	}

	return testutil.NewSystem(ctx, t, k.VFS(), mntns)
}

// newTestConnection creates a fuse connection that the sentry can communicate with
// and the FD for the server to communicate with.
func newTestConnection(system *testutil.System, k *kernel.Kernel, maxActiveRequests uint64) (*connection, *vfs.FileDescription, error) {
	fuseDev := &DeviceFD{}

	vd := system.VFS.NewAnonVirtualDentry("fuse")
	defer vd.DecRef(system.Ctx)
	if err := fuseDev.vfsfd.Init(fuseDev, linux.O_RDWR, vd.Mount(), vd.Dentry(), &vfs.FileDescriptionOptions{}); err != nil {
		return nil, nil, err
	}

	fsopts := filesystemOptions{
		maxActiveRequests: maxActiveRequests,
	}
	fuseDev.mu.Lock()
	conn, err := newFUSEConnection(system.Ctx, fuseDev, &fsopts)
	if err != nil {
		return nil, nil, err
	}
	fuseDev.conn = conn
	fuseDev.mu.Unlock()

	// Fake the connection being properly initialized for testing purposes.
	conn.mu.Lock()
	conn.connInitSuccess = true
	conn.mu.Unlock()
	return conn, &fuseDev.vfsfd, nil
}

// newTestFilesystem creates a filesystem that the sentry can communicate with
// and the FD for the server to communicate with.
func newTestFilesystem(system *testutil.System, fd *vfs.FileDescription, maxActiveRequests uint64) (*filesystem, error) {
	fuseFD, ok := fd.Impl().(*DeviceFD)
	if !ok {
		return nil, fmt.Errorf("newTestFilesystem: FD is %T, not a FUSE device", fd)
	}
	fsopts := filesystemOptions{
		maxActiveRequests: maxActiveRequests,
	}

	fuseFD.mu.Lock()
	defer fuseFD.mu.Unlock()
	fs, err := newFUSEFilesystem(system.Ctx, system.VFS, &FilesystemType{}, fuseFD, 0, &fsopts)
	if err != nil {
		return nil, err
	}
	return fs, nil
}
