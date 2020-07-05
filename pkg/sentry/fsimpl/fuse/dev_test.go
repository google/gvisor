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

package fuse

import (
	"fmt"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/testutil"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/tmpfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/tools/go_marshal/marshal"
	"io"
	"testing"
)

const testOpcode linux.FUSEOpcode = 1000

type testObject struct {
	opcode linux.FUSEOpcode
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (t *testObject) SizeBytes() int {
	return	(*linux.FUSEOpcode)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (t *testObject) MarshalBytes(dst []byte) {
	t.opcode.MarshalBytes(dst[:t.opcode.SizeBytes()])
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (t *testObject) UnmarshalBytes(src []byte) {
	t.opcode.UnmarshalBytes(src[:t.opcode.SizeBytes()])
}

// Packed implements marshal.Marshallable.Packed.
func (t *testObject) Packed() bool {
	return t.opcode.Packed()
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (t *testObject) MarshalUnsafe(dst []byte) {
	t.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (t *testObject) UnmarshalUnsafe(src []byte) {
	t.UnmarshalBytes(src)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (t *testObject) CopyOutN(task marshal.Task, addr usermem.Addr, limit int) (int, error) {
	panic("not implemented")
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (t *testObject) CopyOut(task marshal.Task, addr usermem.Addr) (int, error) {
	panic("not implemented")
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (t *testObject) CopyIn(task marshal.Task, addr usermem.Addr) (int, error) {
	panic("not implemented")
}

// WriteTo implements io.WriterTo.WriteTo.
func (t *testObject) WriteTo(w io.Writer) (int64, error) {
	panic("not implemented")
}

func setup(t *testing.T) *testutil.System {
	k, err := testutil.Boot()
	if err != nil {
		t.Fatalf("Error creating kernel: %v", err)
	}

	ctx := k.SupervisorContext()
	creds := auth.CredentialsFromContext(ctx)

	k.VFS().MustRegisterFilesystemType(Name, &FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserList: true,
		AllowUserMount: true,
	})

	mntns, err := k.VFS().NewMountNamespace(ctx, creds, "", tmpfs.Name, &vfs.GetFilesystemOptions{})
	if err != nil {
		t.Fatalf("NewMountNamespace(): %v", err)
	}

	return testutil.NewSystem(ctx, t, k.VFS(), mntns)
}

// newTestConnection creates a fuse connection that the sentry can communicate with
// and the FD for the server to communicate with.
func newTestConnection(system *testutil.System, k *kernel.Kernel) (*testutil.System, *Connection, *vfs.FileDescription, error) {
	vfsObj := &vfs.VirtualFilesystem{}
	fuseDev := &DeviceFD{}

	if err := vfsObj.Init(); err != nil {
		return nil, nil, nil, err
	}

	vd := vfsObj.NewAnonVirtualDentry("genCountFD")
	defer vd.DecRef()
	if err := fuseDev.vfsfd.Init(fuseDev, 0, vd.Mount(), vd.Dentry(), &vfs.FileDescriptionOptions{}); err != nil {
		return nil, nil, nil, err
	}

	tc := k.NewThreadGroup(nil, k.RootPIDNamespace(), kernel.NewSignalHandlers(), linux.SIGCHLD, k.GlobalInit().Limits())
	task, err := testutil.CreateTask(system.Ctx, fmt.Sprintf("fuse-task"), tc, system.MntNs, system.Root, system.Root)
	if err != nil {
		return nil, nil, nil, err
	}
	task.Start(k.TaskSet().Root.IDOfTask(task))

	// Use the task as the context.
	taskSystem := system.WithTemporaryContext(task)

	return taskSystem, NewFUSEConnection(taskSystem.Ctx, &fuseDev.vfsfd), &fuseDev.vfsfd, nil
}

// TestEmptyQueue exercises the behaviour when no requests are queued up.
func TestEmptyQueue(t *testing.T) {
	s := setup(t)
	defer s.Destroy()

	k := kernel.KernelFromContext(s.Ctx)
	s, _, fd, err := newTestConnection(s, k)
	if err != nil {
		t.Fatalf("newTestConnection: %v", err)
	}

	buf := make([]byte, 2)
	ioseq := usermem.BytesIOSequence(buf)
	_, err = fd.Read(s.Ctx, ioseq, vfs.ReadOptions{})
	if err != syserror.EAGAIN {
		t.Fatalf("Expected error: %v but got: %v", syserror.EAGAIN, err)
	}
}

func TestCallAndResolve(t *testing.T) {
	s := setup(t)
	defer s.Destroy()

	k := kernel.KernelFromContext(s.Ctx)
	creds := auth.CredentialsFromContext(s.Ctx)

	s, fuseConn, fd, err := newTestConnection(s, k)
	if err != nil {
		t.Fatalf("newTestConnection: %v", err)
	}

	// Queue up a request.
	testObj := &testObject{
		opcode:testOpcode,
	}
	testPid := uint32(1)
	testInode := uint64(1)
	req, err := fuseConn.NewRequest(creds, testPid, testInode, testOpcode, testObj)
	if err != nil {
		t.Fatalf("NewRequest creation failed: %v", err)
	}

	taskCtxKey := kernel.CtxTask
	taskCtxValue := s.Ctx.Value(taskCtxKey)
	if taskCtxValue == nil {
		t.Fatalf("Task not found: %v", err)
	}
	task := taskCtxValue.(*kernel.Task)

	respFuture, err := fuseConn.CallFuture(task, req)
	if err != nil {
		t.Fatalf("NewRequest creation failed: %v", err)
	}
	_ = respFuture

	// Read the request.
	hdrLen := uint32((*linux.FUSEHeaderIn)(nil).SizeBytes())
	payloadLen := uint32(testObj.SizeBytes())
	buf := make([]byte, hdrLen + payloadLen)
	ioseq := usermem.BytesIOSequence(buf)
	n, err := fd.Read(s.Ctx, ioseq, vfs.ReadOptions{})
	if err != nil {
		t.Fatalf("Read failed :%v", err)
	}

	if n <= 0 {
		t.Fatalf("Read read no bytes")
	}

	var readFUSEHeaderIn linux.FUSEHeaderIn
	var readPayload testObject
	readFUSEHeaderIn.UnmarshalUnsafe(buf[:hdrLen])
	readPayload.UnmarshalUnsafe(buf[hdrLen:])

	if readPayload.opcode != testOpcode || readFUSEHeaderIn.Opcode != testOpcode {
		t.Fatalf("read incorrect data. Header: %v, Payload: %v", readFUSEHeaderIn, readPayload)
	}

	//buf := make([]byte, hdrLen + payloadLen)
	//ioseq := usermem.BytesIOSequence(buf)
	//n, err := fd.Read(s.Ctx, ioseq, vfs.ReadOptions{})
	//if err != nil {
	//	t.Fatalf("Read failed :%v", err)
	//}
	//
	//
	//var newTestObject testObject
	//if err := resp.UnmarshalPayload(&newTestObject); err != nil {
	//	t.Fatalf("Unmarshalling payload error: %v", err)
	//}

}

func TestConcurrentRequests(t *testing.T) {
}

