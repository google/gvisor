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
	"bytes"
	"fmt"
	"math"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/testutil"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
)

func TestFUSEIoctl(t *testing.T) {
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
	defer fd.DecRef(s.Ctx)
	fdNum, err := task.FDTable().NewFD(s.Ctx, 0, fd, kernel.FDFlags{})
	if err != nil {
		t.Fatalf("NewFD failed: %v", err)
	}

	ctx := vfs.WithMountNamespace(context.WithValue(s.Ctx, kernel.CtxTask, task), s.MntNs)
	mountPop := vfs.PathOperation{Root: s.Root, Start: s.Root, Path: fspath.Parse("/fuse")}
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
	defer func() {
		if err := s.VFS.UmountAt(ctx, task.Credentials(), &mountPop, &vfs.UmountOptions{}); err != nil {
			t.Errorf("UmountAt(/fuse) failed: %v", err)
		}
	}()
	conn.setInitialized()

	const argAddr = 16
	termiosSize := uint32((*linux.Termios)(nil).SizeBytes())
	termios2Size := uint32((*linux.KernelTermios)(nil).SizeBytes())
	wsSize := uint32((*linux.Winsize)(nil).SizeBytes())
	wantSizes := map[uint32][2]uint32{
		linux.TCGETS:     {0, termiosSize},
		linux.TCSETS:     {termiosSize, 0},
		linux.TCSETSW:    {termiosSize, 0},
		linux.TCSETSF:    {termiosSize, 0},
		linux.TCGETS2:    {0, termios2Size},
		linux.TCSETS2:    {termios2Size, 0},
		linux.TCSETSW2:   {termios2Size, 0},
		linux.TCSETSF2:   {termios2Size, 0},
		linux.TIOCGWINSZ: {0, wsSize},
	}

	marshalIoctlOut := func(out linux.FUSEIoctlOut, payload []byte) []byte {
		reply := make([]byte, out.SizeBytes()+len(payload))
		out.MarshalUnsafe(reply[:out.SizeBytes()])
		copy(reply[out.SizeBytes():], payload)
		return reply
	}

	var savedTermios linux.Termios
	var savedTermios2 linux.KernelTermios
	fixedWS := linux.Winsize{Row: 50, Col: 132}
	var overrideMu sync.Mutex
	var replyOverride func(unique linux.FUSEOpID)
	var serverIoctls atomic.Int32
	killServer := make(chan struct{}, 1)
	serverDone := make(chan struct{})

	go func() {
		defer close(serverDone)
		for {
			inBuf := make([]byte, linux.FUSE_MIN_READ_BUFFER)
			n, serverKilled, err := ReadTest(task, fd, usermem.BytesIOSequence(inBuf), killServer)
			if err != nil || serverKilled {
				if err != nil {
					t.Errorf("ReadTest failed: %v", err)
				}
				return
			}
			var hdr linux.FUSEHeaderIn
			payloadBuf := hdr.UnmarshalUnsafe(inBuf[:n])

			switch hdr.Opcode {
			case linux.FUSE_LOOKUP:
				out := linux.FUSEEntryOut{
					NodeID: 2, Generation: 1, EntryValid: 3600, AttrValid: 3600,
					Attr: linux.FUSEAttr{Ino: 2, Size: 1024, Mode: linux.S_IFREG | 0644, Nlink: 1},
				}
				replyBuf := make([]byte, out.SizeBytes())
				out.MarshalBytes(replyBuf)
				sendSuccessReply(s.Ctx, t, fd, hdr.Unique, replyBuf)
			case linux.FUSE_ACCESS, linux.FUSE_FLUSH, linux.FUSE_RELEASE:
				sendSuccessReply(s.Ctx, t, fd, hdr.Unique, nil)
			case linux.FUSE_OPEN:
				out := linux.FUSEOpenOut{Fh: 42}
				replyBuf := make([]byte, out.SizeBytes())
				out.MarshalBytes(replyBuf)
				sendSuccessReply(s.Ctx, t, fd, hdr.Unique, replyBuf)
			case linux.FUSE_IOCTL:
				serverIoctls.Add(1)
				var ioctlIn linux.FUSEIoctlIn
				inData := ioctlIn.UnmarshalUnsafe(payloadBuf)
				want, known := wantSizes[ioctlIn.Cmd]
				if !known || ioctlIn.Fh != 42 || ioctlIn.Arg != 0 || ioctlIn.Flags != 0 ||
					ioctlIn.InSize != want[0] || ioctlIn.OutSize != want[1] || uint32(len(inData)) != want[0] {
					t.Errorf("unexpected FUSE_IOCTL: %+v payloadLen=%d", ioctlIn, len(inData))
					sendErrorReply(s.Ctx, t, fd, hdr.Unique, -int32(unix.EINVAL))
					continue
				}
				overrideMu.Lock()
				override := replyOverride
				overrideMu.Unlock()
				if override != nil {
					override(hdr.Unique)
					continue
				}
				switch ioctlIn.Cmd {
				case linux.TCGETS:
					raw := make([]byte, termiosSize)
					savedTermios.MarshalUnsafe(raw)
					sendSuccessReply(s.Ctx, t, fd, hdr.Unique, marshalIoctlOut(linux.FUSEIoctlOut{}, raw))
				case linux.TCSETS, linux.TCSETSW, linux.TCSETSF:
					savedTermios.UnmarshalUnsafe(inData)
					sendSuccessReply(s.Ctx, t, fd, hdr.Unique, marshalIoctlOut(linux.FUSEIoctlOut{}, nil))
				case linux.TCGETS2:
					raw := make([]byte, termios2Size)
					savedTermios2.MarshalUnsafe(raw)
					sendSuccessReply(s.Ctx, t, fd, hdr.Unique, marshalIoctlOut(linux.FUSEIoctlOut{}, raw))
				case linux.TCSETS2, linux.TCSETSW2, linux.TCSETSF2:
					savedTermios2.UnmarshalUnsafe(inData)
					sendSuccessReply(s.Ctx, t, fd, hdr.Unique, marshalIoctlOut(linux.FUSEIoctlOut{}, nil))
				case linux.TIOCGWINSZ:
					raw := make([]byte, wsSize)
					fixedWS.MarshalUnsafe(raw)
					sendSuccessReply(s.Ctx, t, fd, hdr.Unique, marshalIoctlOut(linux.FUSEIoctlOut{Result: 3}, raw))
				}
			default:
				t.Errorf("unexpected opcode: %v", hdr.Opcode)
				sendErrorReply(s.Ctx, t, fd, hdr.Unique, -int32(unix.ENOSYS))
			}
		}
	}()
	defer func() {
		killServer <- struct{}{}
		<-serverDone
	}()

	filePop := vfs.PathOperation{Root: s.Root, Start: s.Root, Path: fspath.Parse("/fuse/ttyfile")}
	fileFD, err := s.VFS.OpenAt(ctx, task.Credentials(), &filePop, &vfs.OpenOptions{Flags: linux.O_RDONLY})
	if err != nil {
		t.Fatalf("OpenAt(/fuse/ttyfile) failed: %v", err)
	}
	defer fileFD.DecRef(ctx)

	mkTermios := func(lflag uint32) []byte {
		tm := linux.Termios{LocalFlags: lflag}
		raw := make([]byte, tm.SizeBytes())
		tm.MarshalUnsafe(raw)
		return raw
	}
	mkTermios2 := func(lflag uint32) []byte {
		tm := linux.KernelTermios{LocalFlags: lflag, InputSpeed: 38400, OutputSpeed: 38400}
		raw := make([]byte, tm.SizeBytes())
		tm.MarshalUnsafe(raw)
		return raw
	}
	wsRaw := make([]byte, fixedWS.SizeBytes())
	fixedWS.MarshalUnsafe(wsRaw)

	for _, tc := range []struct {
		name      string
		setCmd    uint32
		setBytes  []byte
		getCmd    uint32
		wantBytes []byte
		wantRet   uintptr
	}{
		{"TCSETS", linux.TCSETS, mkTermios(linux.ISIG), linux.TCGETS, mkTermios(linux.ISIG), 0},
		{"TCSETSW", linux.TCSETSW, mkTermios(linux.ICANON), linux.TCGETS, mkTermios(linux.ICANON), 0},
		{"TCSETSF", linux.TCSETSF, mkTermios(linux.ECHO), linux.TCGETS, mkTermios(linux.ECHO), 0},
		{"TCSETS2", linux.TCSETS2, mkTermios2(linux.ISIG), linux.TCGETS2, mkTermios2(linux.ISIG), 0},
		{"TCSETSW2", linux.TCSETSW2, mkTermios2(linux.ICANON), linux.TCGETS2, mkTermios2(linux.ICANON), 0},
		{"TCSETSF2", linux.TCSETSF2, mkTermios2(linux.ECHO), linux.TCGETS2, mkTermios2(linux.ECHO), 0},
		{"TIOCGWINSZ", 0, nil, linux.TIOCGWINSZ, wsRaw, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mem := bytes.Repeat([]byte{0xa5}, 96)
			uio := &usermem.BytesIO{Bytes: mem}
			if tc.setCmd != 0 {
				copy(mem[argAddr:], tc.setBytes)
				if _, err := fileFD.Ioctl(ctx, uio, 0, arch.SyscallArguments{{}, {Value: uintptr(tc.setCmd)}, {Value: argAddr}}); err != nil {
					t.Fatalf("Ioctl(%#x) failed: %v", tc.setCmd, err)
				}
				for i := range mem {
					mem[i] = 0xa5
				}
			}
			ret, err := fileFD.Ioctl(ctx, uio, 0, arch.SyscallArguments{{}, {Value: uintptr(tc.getCmd)}, {Value: argAddr}})
			if err != nil || ret != tc.wantRet {
				t.Fatalf("Ioctl(%#x) = (%d, %v), want (%d, nil)", tc.getCmd, ret, err, tc.wantRet)
			}
			if got := mem[argAddr : argAddr+len(tc.wantBytes)]; !bytes.Equal(got, tc.wantBytes) {
				t.Errorf("Ioctl(%#x) output = %x, want %x", tc.getCmd, got, tc.wantBytes)
			}
			if mem[argAddr-1] != 0xa5 || mem[argAddr+len(tc.wantBytes)] != 0xa5 {
				t.Errorf("Ioctl(%#x) clobbered sentinel bytes: (%#x, %#x)", tc.getCmd, mem[argAddr-1], mem[argAddr+len(tc.wantBytes)])
			}
		})
	}

	nonOwnerCreds := auth.NewUserCredentials(1000, 1000, nil, nil, s.Creds.UserNamespace)
	nonOwnerCtx := context.WithValue(ctx, auth.CtxCredentials, nonOwnerCreds)

	for _, tc := range []struct {
		name           string
		callCtx        context.Context
		cmd            uint32
		bufLen         int
		override       func(unique linux.FUSEOpID)
		wantErrno      unix.Errno
		wantNoServerOp bool
		wantFirstByte  byte
	}{
		{name: "FICLONEUnchanged", callCtx: ctx, cmd: linux.FICLONE, bufLen: 96, wantErrno: unix.EOPNOTSUPP, wantNoServerOp: true},
		{name: "NonOwnerNonWhitelistedUnchanged", callCtx: nonOwnerCtx, cmd: linux.FICLONE, bufLen: 96, wantErrno: unix.EOPNOTSUPP, wantNoServerOp: true},
		{name: "NonWhitelistedIORNotForwarded", callCtx: ctx, cmd: linux.IOR('z', 1, 4), bufLen: 96, wantErrno: unix.ENOTTY, wantNoServerOp: true},
		{name: "NonWhitelistedUnencodedNotForwarded", callCtx: ctx, cmd: linux.TIOCGPGRP, bufLen: 96, wantErrno: unix.ENOTTY, wantNoServerOp: true},
		{name: "TIOCSWINSZNotForwarded", callCtx: ctx, cmd: linux.TIOCSWINSZ, bufLen: 96, wantErrno: unix.ENOTTY, wantNoServerOp: true},
		{name: "NonMountOwnerDenied", callCtx: nonOwnerCtx, cmd: linux.TCGETS, bufLen: 96, wantErrno: unix.EACCES, wantNoServerOp: true},
		{name: "CopyInEFAULT", callCtx: ctx, cmd: linux.TCSETS, bufLen: argAddr + 8, wantErrno: unix.EFAULT, wantNoServerOp: true},
		{name: "CopyOutEFAULT", callCtx: ctx, cmd: linux.TCGETS, bufLen: argAddr + 8, wantErrno: unix.EFAULT},
		{
			name: "HeaderENOSYSMapsToENOTTY", callCtx: ctx, cmd: linux.TIOCGWINSZ, bufLen: 96,
			override:  func(u linux.FUSEOpID) { sendErrorReply(s.Ctx, t, fd, u, -int32(unix.ENOSYS)) },
			wantErrno: unix.ENOTTY,
		},
		{
			name: "HeaderEPERMPropagated", callCtx: ctx, cmd: linux.TIOCGWINSZ, bufLen: 96,
			override:  func(u linux.FUSEOpID) { sendErrorReply(s.Ctx, t, fd, u, -int32(unix.EPERM)) },
			wantErrno: unix.EPERM,
		},
		{
			name: "OutResultENOSYSMapsToENOTTY", callCtx: ctx, cmd: linux.TIOCGWINSZ, bufLen: 96,
			override: func(u linux.FUSEOpID) {
				sendSuccessReply(s.Ctx, t, fd, u, marshalIoctlOut(linux.FUSEIoctlOut{Result: -int32(unix.ENOSYS)}, nil))
			},
			wantErrno: unix.ENOTTY,
		},
		{
			name: "InvalidResultErrnoIsEINVAL", callCtx: ctx, cmd: linux.TIOCGWINSZ, bufLen: 96,
			override: func(u linux.FUSEOpID) {
				sendSuccessReply(s.Ctx, t, fd, u, marshalIoctlOut(linux.FUSEIoctlOut{Result: -4096}, nil))
			},
			wantErrno: unix.EINVAL,
		},
		{
			name: "MinInt32ResultErrnoIsEINVAL", callCtx: ctx, cmd: linux.TIOCGWINSZ, bufLen: 96,
			override: func(u linux.FUSEOpID) {
				sendSuccessReply(s.Ctx, t, fd, u, marshalIoctlOut(linux.FUSEIoctlOut{Result: math.MinInt32}, nil))
			},
			wantErrno: unix.EINVAL,
		},
		{
			name: "NegativeResultPreservedWithPayload", callCtx: ctx, cmd: linux.TIOCGWINSZ, bufLen: 96,
			override: func(u linux.FUSEOpID) {
				sendSuccessReply(s.Ctx, t, fd, u, marshalIoctlOut(linux.FUSEIoctlOut{Result: -int32(unix.EPERM)}, []byte{0x99, 0, 0, 0}))
			},
			wantErrno: unix.EPERM, wantFirstByte: 0x99,
		},
		{
			name: "RetryFlagRejected", callCtx: ctx, cmd: linux.TIOCGWINSZ, bufLen: 96,
			override: func(u linux.FUSEOpID) {
				sendSuccessReply(s.Ctx, t, fd, u, marshalIoctlOut(linux.FUSEIoctlOut{Flags: linux.FUSE_IOCTL_RETRY}, []byte{0x77, 0, 0, 0}))
			},
			wantErrno: unix.EIO,
		},
		{
			name: "OversizedPayloadRejected", callCtx: ctx, cmd: linux.TIOCGWINSZ, bufLen: 96,
			override: func(u linux.FUSEOpID) {
				sendSuccessReply(s.Ctx, t, fd, u, marshalIoctlOut(linux.FUSEIoctlOut{}, bytes.Repeat([]byte{0x77}, int(wsSize)+1)))
			},
			wantErrno: unix.EIO,
		},
		{
			name: "ShortPayloadRejected", callCtx: ctx, cmd: linux.TIOCGWINSZ, bufLen: 96,
			override: func(u linux.FUSEOpID) {
				sendSuccessReply(s.Ctx, t, fd, u, marshalIoctlOut(linux.FUSEIoctlOut{}, bytes.Repeat([]byte{0x77}, int(wsSize)-1)))
			},
			wantErrno: unix.EIO,
		},
		{
			name: "ShortReplyRejected", callCtx: ctx, cmd: linux.TIOCGWINSZ, bufLen: 96,
			override:  func(u linux.FUSEOpID) { sendSuccessReply(s.Ctx, t, fd, u, []byte{1, 2, 3, 4}) },
			wantErrno: unix.EINVAL,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			overrideMu.Lock()
			replyOverride = tc.override
			overrideMu.Unlock()
			defer func() {
				overrideMu.Lock()
				replyOverride = nil
				overrideMu.Unlock()
			}()

			before := serverIoctls.Load()
			uio := &usermem.BytesIO{Bytes: make([]byte, tc.bufLen)}
			_, err := fileFD.Ioctl(tc.callCtx, uio, 0, arch.SyscallArguments{{}, {Value: uintptr(tc.cmd)}, {Value: argAddr}})
			if wantErr := linuxerr.ErrorFromUnix(tc.wantErrno); err != wantErr {
				t.Errorf("Ioctl(%#x) error = %v, want %v", tc.cmd, err, wantErr)
			}
			if uio.Bytes[argAddr] != tc.wantFirstByte {
				t.Errorf("Ioctl(%#x) byte at %d = %#x, want %#x", tc.cmd, argAddr, uio.Bytes[argAddr], tc.wantFirstByte)
			}
			wantServerIoctls := before + 1
			if tc.wantNoServerOp {
				wantServerIoctls = before
			}
			if got := serverIoctls.Load(); got != wantServerIoctls {
				t.Errorf("server received %d ioctls, want %d", got, wantServerIoctls)
			}
		})
	}
}
