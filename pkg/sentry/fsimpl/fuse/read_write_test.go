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
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/testutil"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
)

// TestFUSEReadError verifies that an error returned by the FUSE server in
// response to FUSE_READ is propagated by ReadInPages rather than being
// treated as EOF (0 bytes read).
func TestFUSEReadError(t *testing.T) {
	s := setup(t)
	defer s.Destroy()

	k := kernel.KernelFromContext(s.Ctx)

	tc := k.NewThreadGroup(k.RootPIDNamespace(), kernel.NewSignalHandlers(), linux.SIGCHLD, k.GlobalInit().Limits())
	task, err := testutil.CreateTask(s.Ctx, "fuse-client", tc, s.MntNs, s.Root, s.Root)
	if err != nil {
		t.Fatalf("CreateTask failed: %v", err)
	}

	conn, fd, err := newTestConnection(s, maxActiveRequestsDefault)
	if err != nil {
		t.Fatalf("newTestConnection failed: %v", err)
	}
	conn.maxRead = uint32(hostarch.PageSize)

	fdNum, err := task.FDTable().NewFD(s.Ctx, 0, fd, kernel.FDFlags{})
	if err != nil {
		t.Fatalf("NewFD failed: %v", err)
	}

	ctx := context.WithValue(s.Ctx, kernel.CtxTask, task)

	mountPop := vfs.PathOperation{
		Root:  s.Root,
		Start: s.Root,
		Path:  fspath.Parse("/fuse"),
	}
	if err := s.VFS.MkdirAt(ctx, task.Credentials(), &mountPop, &vfs.MkdirOptions{Mode: 0755}); err != nil {
		t.Fatalf("MkdirAt(/fuse) failed: %v", err)
	}

	mntOpts := &vfs.MountOptions{
		GetFilesystemOptions: vfs.GetFilesystemOptions{
			Data: fmt.Sprintf("fd=%d,user_id=0,group_id=0,rootmode=40755", fdNum),
		},
	}
	if _, err := s.VFS.MountAt(ctx, task.Credentials(), "", &mountPop, Name, mntOpts); err != nil {
		t.Fatalf("MountAt(/fuse) failed: %v", err)
	}

	conn.setInitialized()

	killServer := make(chan struct{}, 1)
	serverDone := make(chan struct{})

	const fileData = "hello world\n"
	readAttempt := 0

	go func() {
		defer close(serverDone)
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
			hdr.UnmarshalUnsafe(inBuf)

			switch hdr.Opcode {
			case linux.FUSE_LOOKUP:
				out := linux.FUSEEntryOut{
					NodeID:     2,
					Generation: 1,
					EntryValid: 3600,
					AttrValid:  3600,
					Attr: linux.FUSEAttr{
						Ino:   2,
						Size:  uint64(len(fileData)),
						Mode:  linux.S_IFREG | 0644,
						Nlink: 1,
					},
				}
				replyBuf := make([]byte, out.SizeBytes())
				out.MarshalBytes(replyBuf)
				sendSuccessReply(s.Ctx, t, fd, hdr.Unique, replyBuf)

			case linux.FUSE_ACCESS, linux.FUSE_FLUSH, linux.FUSE_RELEASE:
				sendSuccessReply(s.Ctx, t, fd, hdr.Unique, nil)

			case linux.FUSE_OPEN:
				out := linux.FUSEOpenOut{
					Fh: 1,
				}
				replyBuf := make([]byte, out.SizeBytes())
				out.MarshalBytes(replyBuf)
				sendSuccessReply(s.Ctx, t, fd, hdr.Unique, replyBuf)

			case linux.FUSE_GETATTR:
				out := linux.FUSEAttrOut{
					AttrValid: 3600,
					Attr: linux.FUSEAttr{
						Ino:   2,
						Size:  uint64(len(fileData)),
						Mode:  linux.S_IFREG | 0644,
						Nlink: 1,
					},
				}
				replyBuf := make([]byte, out.SizeBytes())
				out.MarshalBytes(replyBuf)
				sendSuccessReply(s.Ctx, t, fd, hdr.Unique, replyBuf)

			case linux.FUSE_READ:
				readAttempt++
				if readAttempt == 1 {
					sendErrorReply(s.Ctx, t, fd, hdr.Unique, -int32(unix.EACCES))
				} else {
					sendSuccessReply(s.Ctx, t, fd, hdr.Unique, []byte(fileData))
				}

			default:
				t.Errorf("Unexpected opcode: %v", hdr.Opcode)
				sendErrorReply(s.Ctx, t, fd, hdr.Unique, -int32(unix.ENOSYS))
			}
		}
	}()

	filePop := vfs.PathOperation{
		Root:  s.Root,
		Start: s.Root,
		Path:  fspath.Parse("/fuse/testfile"),
	}
	fileFD, err := s.VFS.OpenAt(ctx, task.Credentials(), &filePop, &vfs.OpenOptions{Flags: linux.O_RDONLY})
	if err != nil {
		t.Fatalf("OpenAt(/fuse/testfile) failed: %v", err)
	}
	defer func() {
		if fileFD != nil {
			fileFD.DecRef(ctx)
		}
		killServer <- struct{}{}
		<-serverDone
	}()

	// First read: server responds with EACCES. The error must be propagated
	// rather than treated as 0-byte EOF.
	buf := make([]byte, len(fileData))
	n, err := fileFD.Read(ctx, usermem.BytesIOSequence(buf), vfs.ReadOptions{})
	if !linuxerr.Equals(linuxerr.EACCES, err) {
		t.Fatalf("Read() error = %v (n=%d), want %v", err, n, linuxerr.EACCES)
	}
	if n != 0 {
		t.Errorf("Read() bytes read = %d, want 0", n)
	}

	// Verify the failed read did not clobber the cached inode size to 0.
	statx, err := fileFD.Stat(ctx, vfs.StatOptions{
		Mask: linux.STATX_SIZE,
		Sync: linux.AT_STATX_DONT_SYNC,
	})
	if err != nil {
		t.Fatalf("Stat() failed: %v", err)
	}
	if statx.Size != uint64(len(fileData)) {
		t.Errorf("Stat() size after failed read = %d, want %d", statx.Size, len(fileData))
	}

	// Second read: server responds with fileData.
	n, err = fileFD.Read(ctx, usermem.BytesIOSequence(buf), vfs.ReadOptions{})
	if err != nil {
		t.Fatalf("second Read() failed: %v", err)
	}
	if got := string(buf[:n]); got != fileData {
		t.Errorf("second Read() = %q, want %q", got, fileData)
	}

	fileFD.DecRef(ctx)
	fileFD = nil
}
