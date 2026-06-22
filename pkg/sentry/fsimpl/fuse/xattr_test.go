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

package fuse

import (
	"fmt"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/testutil"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
)

func TestFUSEXattr(t *testing.T) {
	s := setup(t)
	defer s.Destroy()

	k := kernel.KernelFromContext(s.Ctx)

	// Create a task for the client.
	tc := k.NewThreadGroup(k.RootPIDNamespace(), kernel.NewSignalHandlers(), linux.SIGCHLD, k.GlobalInit().Limits())
	task, err := testutil.CreateTask(s.Ctx, "fuse-client", tc, s.MntNs, s.Root, s.Root)
	if err != nil {
		t.Fatalf("CreateTask failed: %v", err)
	}

	// Create FUSE connection.
	conn, fd, err := newTestConnection(s, maxActiveRequestsDefault)
	if err != nil {
		t.Fatalf("newTestConnection failed: %v", err)
	}

	// Install FD into the task.
	fdNum, err := task.FDTable().NewFD(s.Ctx, 0, fd, kernel.FDFlags{})
	if err != nil {
		t.Fatalf("NewFD failed: %v", err)
	}

	// Create context wrapping task to avoid goroutine assertion in race builds.
	ctx := context.WithValue(s.Ctx, kernel.CtxTask, task)

	// Create mount point /fuse.
	pop := vfs.PathOperation{
		Root:  s.Root,
		Start: s.Root,
		Path:  fspath.Parse("/fuse"),
	}
	// Use wrapped context for VFS operations to ensure kernel task is available
	// without triggering task goroutine assertions.
	if err := s.VFS.MkdirAt(ctx, task.Credentials(), &pop, &vfs.MkdirOptions{Mode: 0755}); err != nil {
		t.Fatalf("MkdirAt(/fuse) failed: %v", err)
	}

	// Mount FUSE.
	mntOpts := &vfs.MountOptions{
		GetFilesystemOptions: vfs.GetFilesystemOptions{
			Data: fmt.Sprintf("fd=%d,user_id=0,group_id=0,rootmode=40755", fdNum),
		},
	}
	if _, err := s.VFS.MountAt(ctx, task.Credentials(), "", &pop, Name, mntOpts); err != nil {
		t.Fatalf("MountAt(/fuse) failed: %v", err)
	}

	// Unblock the connection so that VFS operations (which call conn.Call) can proceed.
	conn.setInitialized()

	// We will run the mock daemon in a goroutine.
	// It will handle requests and we will signal it when we are done.
	killServer := make(chan struct{}, 1)
	serverDone := make(chan struct{})

	// Target xattr details.
	xattrName := "user.test"
	xattrVal := "value.test"
	newXattrVal := "value.new"

	go func() {
		defer close(serverDone)
		// Server loop.
		for {
			inBuf := make([]byte, linux.FUSE_MIN_READ_BUFFER)
			inIOseq := usermem.BytesIOSequence(inBuf)

			n, serverKilled, err := ReadTest(task, fd, inIOseq, killServer)
			if err != nil {
				t.Errorf("ReadTest failed: %v", err)
				return
			}
			if serverKilled {
				return
			}
			if n <= 0 {
				t.Errorf("ReadTest read no bytes")
				return
			}

			var hdr linux.FUSEHeaderIn
			payloadBuf := hdr.UnmarshalUnsafe(inBuf)

			switch hdr.Opcode {
			case linux.FUSE_GETXATTR:
				var getXattrHdr linux.FUSEGetXattrHdr
				nameBuf := getXattrHdr.UnmarshalUnsafe(payloadBuf)
				name, _ := readCString(nameBuf)

				if name != xattrName {
					t.Errorf("GetXattr: expected name %q, got %q", xattrName, name)
					sendErrorReply(s.Ctx, t, fd, hdr.Unique, -int32(unix.ENODATA))
					continue
				}

				if getXattrHdr.Size == 0 {
					out := linux.FUSEGetXattrOut{
						Size: uint32(len(xattrVal)),
					}
					replyBuf := make([]byte, out.SizeBytes())
					out.MarshalBytes(replyBuf)
					sendSuccessReply(s.Ctx, t, fd, hdr.Unique, replyBuf)
				} else {
					sendSuccessReply(s.Ctx, t, fd, hdr.Unique, []byte(xattrVal))
				}

			case linux.FUSE_SETXATTR:
				var setXattrHdr linux.FUSESetXattrHdr
				restBuf := setXattrHdr.UnmarshalUnsafe(payloadBuf)
				name, valBuf := readCString(restBuf)
				val := valBuf[:setXattrHdr.Size]

				if name != xattrName {
					t.Errorf("SetXattr: expected name %q, got %q", xattrName, name)
					sendErrorReply(s.Ctx, t, fd, hdr.Unique, -int32(unix.EINVAL))
					continue
				}
				if string(val) != newXattrVal {
					t.Errorf("SetXattr: expected value %q, got %q", newXattrVal, val)
					sendErrorReply(s.Ctx, t, fd, hdr.Unique, -int32(unix.EINVAL))
					continue
				}

				// Success reply.
				sendSuccessReply(s.Ctx, t, fd, hdr.Unique, nil)

			case linux.FUSE_LISTXATTR:
				var listXattrHdr linux.FUSEGetXattrHdr
				listXattrHdr.UnmarshalUnsafe(payloadBuf)

				replyData := []byte(xattrName + "\x00")
				if listXattrHdr.Size == 0 {
					out := linux.FUSEGetXattrOut{
						Size: uint32(len(replyData)),
					}
					replyBuf := make([]byte, out.SizeBytes())
					out.MarshalBytes(replyBuf)
					sendSuccessReply(s.Ctx, t, fd, hdr.Unique, replyBuf)
				} else {
					sendSuccessReply(s.Ctx, t, fd, hdr.Unique, replyData)
				}

			case linux.FUSE_REMOVEXATTR:
				name, _ := readCString(payloadBuf)

				if name != xattrName {
					t.Errorf("RemoveXattr: expected name %q, got %q", xattrName, name)
					sendErrorReply(s.Ctx, t, fd, hdr.Unique, -int32(unix.ENODATA))
					continue
				}

				// Success reply.
				sendSuccessReply(s.Ctx, t, fd, hdr.Unique, nil)

			default:
				t.Errorf("Unexpected opcode: %v", hdr.Opcode)
				sendErrorReply(s.Ctx, t, fd, hdr.Unique, -int32(unix.ENOSYS))
			}
		}
	}()

	// Perform operations and verify.

	// 1. GetXattr (query size)
	val, err := s.VFS.GetXattrAt(s.Ctx, task.Credentials(), &pop, &vfs.GetXattrOptions{
		Name: xattrName,
		Size: 0,
	})
	if err != nil {
		t.Fatalf("GetXattrAt (size) failed: %v", err)
	}
	if len(val) != len(xattrVal) {
		t.Errorf("GetXattrAt (size): expected length %d, got %d", len(xattrVal), len(val))
	}

	// GetXattr (actual value)
	val, err = s.VFS.GetXattrAt(s.Ctx, task.Credentials(), &pop, &vfs.GetXattrOptions{
		Name: xattrName,
		Size: 100,
	})
	if err != nil {
		t.Fatalf("GetXattrAt (value) failed: %v", err)
	}
	if val != xattrVal {
		t.Errorf("GetXattrAt (value): expected %q, got %q", xattrVal, val)
	}

	// 2. SetXattr
	err = s.VFS.SetXattrAt(s.Ctx, task.Credentials(), &pop, &vfs.SetXattrOptions{
		Name:  xattrName,
		Value: newXattrVal,
	})
	if err != nil {
		t.Fatalf("SetXattrAt failed: %v", err)
	}

	// 3. ListXattr (query size)
	names, err := s.VFS.ListXattrAt(s.Ctx, task.Credentials(), &pop, 0)
	if err != nil {
		t.Fatalf("ListXattrAt (size) failed: %v", err)
	}
	totalLen := 0
	for _, name := range names {
		totalLen += len(name) + 1
	}
	expectedLen := len(xattrName) + 1
	if totalLen != expectedLen {
		t.Errorf("ListXattrAt (size): expected total length %d, got %d", expectedLen, totalLen)
	}

	// ListXattr (actual names)
	names, err = s.VFS.ListXattrAt(s.Ctx, task.Credentials(), &pop, 100)
	if err != nil {
		t.Fatalf("ListXattrAt (names) failed: %v", err)
	}
	if len(names) != 1 || names[0] != xattrName {
		t.Errorf("ListXattrAt (names): expected [%q], got %v", xattrName, names)
	}

	// 4. RemoveXattr
	err = s.VFS.RemoveXattrAt(s.Ctx, task.Credentials(), &pop, xattrName)
	if err != nil {
		t.Fatalf("RemoveXattrAt failed: %v", err)
	}

	// Clean up.
	killServer <- struct{}{}
	<-serverDone
}

func sendErrorReply(ctx context.Context, t *testing.T, fd *vfs.FileDescription, unique linux.FUSEOpID, errno int32) {
	outBuf := make([]byte, linux.SizeOfFUSEHeaderOut)
	outHeader := linux.FUSEHeaderOut{
		Len:    linux.SizeOfFUSEHeaderOut,
		Error:  errno,
		Unique: unique,
	}
	outHeader.MarshalUnsafe(outBuf)
	outIOseq := usermem.BytesIOSequence(outBuf)
	if _, err := fd.Write(ctx, outIOseq, vfs.WriteOptions{}); err != nil {
		t.Errorf("Write error reply failed: %v", err)
	}
}

func sendSuccessReply(ctx context.Context, t *testing.T, fd *vfs.FileDescription, unique linux.FUSEOpID, payload []byte) {
	payloadLen := uint32(len(payload))
	outBuf := make([]byte, linux.SizeOfFUSEHeaderOut+payloadLen)
	outHeader := linux.FUSEHeaderOut{
		Len:    linux.SizeOfFUSEHeaderOut + payloadLen,
		Error:  0,
		Unique: unique,
	}
	outHeader.MarshalUnsafe(outBuf[:linux.SizeOfFUSEHeaderOut])
	if payloadLen > 0 {
		copy(outBuf[linux.SizeOfFUSEHeaderOut:], payload)
	}
	outIOseq := usermem.BytesIOSequence(outBuf)
	if _, err := fd.Write(ctx, outIOseq, vfs.WriteOptions{}); err != nil {
		t.Errorf("Write success reply failed: %v", err)
	}
}

func readCString(buf []byte) (string, []byte) {
	for i, b := range buf {
		if b == 0 {
			return string(buf[:i]), buf[i+1:]
		}
	}
	return string(buf), nil
}
