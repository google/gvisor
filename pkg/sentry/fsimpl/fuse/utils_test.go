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
	"io"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/testutil"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"

	"gvisor.dev/gvisor/pkg/hostarch"
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
	fs, err := newFUSEFilesystem(system.Ctx, system.VFS, &FilesystemType{}, fuseDev, 0, &fsopts)
	if err != nil {
		return nil, nil, err
	}
	return fs.conn, &fuseDev.vfsfd, nil
}

type testPayload struct {
	marshal.StubMarshallable
	data uint32
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (t *testPayload) SizeBytes() int {
	return 4
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (t *testPayload) MarshalBytes(dst []byte) {
	hostarch.ByteOrder.PutUint32(dst[:4], t.data)
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (t *testPayload) UnmarshalBytes(src []byte) {
	*t = testPayload{data: hostarch.ByteOrder.Uint32(src[:4])}
}

// Packed implements marshal.Marshallable.Packed.
func (t *testPayload) Packed() bool {
	return true
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (t *testPayload) MarshalUnsafe(dst []byte) {
	t.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (t *testPayload) UnmarshalUnsafe(src []byte) {
	t.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (t *testPayload) CopyOutN(task marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
	panic("not implemented")
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (t *testPayload) CopyOut(task marshal.CopyContext, addr hostarch.Addr) (int, error) {
	panic("not implemented")
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (t *testPayload) CopyIn(task marshal.CopyContext, addr hostarch.Addr) (int, error) {
	panic("not implemented")
}

// WriteTo implements io.WriterTo.WriteTo.
func (t *testPayload) WriteTo(w io.Writer) (int64, error) {
	panic("not implemented")
}
