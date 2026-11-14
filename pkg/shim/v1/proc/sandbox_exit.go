// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package proc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/containerd/log"
	"golang.org/x/sys/unix"
)

func receiveSandboxPidfd(ctx context.Context, socket *net.UnixListener) (fd int, err error) {
	defer func() {
		if errors.Is(err, net.ErrClosed) && context.Cause(ctx) != nil {
			err = context.Cause(ctx)
		}
	}()
	stop := context.AfterFunc(ctx, func() { socket.Close() })
	defer stop()
	conn, err := socket.AcceptUnix()
	if err != nil {
		return -1, err
	}
	defer conn.Close()
	stopRead := context.AfterFunc(ctx, func() { conn.Close() })
	defer stopRead()
	raw, err := conn.SyscallConn()
	if err != nil {
		return -1, err
	}
	var data [16]byte
	control := make([]byte, unix.CmsgSpace(4))
	var n, controlLen, flags int
	var recvErr error
	if err := raw.Read(func(fd uintptr) bool {
		for {
			n, controlLen, flags, _, recvErr = unix.Recvmsg(int(fd), data[:], control, unix.MSG_CMSG_CLOEXEC)
			if recvErr != unix.EINTR {
				return recvErr != unix.EAGAIN
			}
		}
	}); err != nil {
		return -1, err
	}
	if recvErr != nil {
		return -1, recvErr
	}
	messages, err := unix.ParseSocketControlMessage(control[:controlLen])
	if err != nil {
		return -1, err
	}
	var fds []int
	for _, message := range messages {
		rights, err := unix.ParseUnixRights(&message)
		if err != nil {
			for _, fd := range fds {
				unix.Close(fd)
			}
			return -1, err
		}
		fds = append(fds, rights...)
	}
	if n == 0 || flags&unix.MSG_CTRUNC != 0 || len(fds) != 1 {
		for _, fd := range fds {
			unix.Close(fd)
		}
		return -1, fmt.Errorf("expected one sandbox pidfd, received %d", len(fds))
	}
	return fds[0], nil
}

// monitorSandboxExit takes ownership of a pidfd from the sandbox's creator.
func (p *Init) monitorSandboxExit(pidfd int) error {
	if err := unix.SetNonblock(pidfd, true); err != nil {
		unix.Close(pidfd)
		return fmt.Errorf("setting sandbox pidfd nonblocking: %w", err)
	}
	file := os.NewFile(uintptr(pidfd), "sandbox-pidfd")
	if err := file.SetReadDeadline(time.Time{}); err != nil {
		file.Close()
		return fmt.Errorf("registering sandbox pidfd with the poller: %w", err)
	}
	raw, err := file.SyscallConn()
	if err != nil {
		file.Close()
		return err
	}
	var cancelled atomic.Bool
	p.cancelSandboxExit = func() {
		cancelled.Store(true)
		file.Close()
	}
	p.sandboxExit = make(chan int, 1)
	go func() {
		defer close(p.sandboxExit)
		defer file.Close()
		var pollErr error
		err := raw.Read(func(fd uintptr) bool {
			poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
			for {
				var n int
				n, pollErr = unix.Poll(poll, 0)
				if pollErr != unix.EINTR {
					return pollErr != nil || n != 0
				}
			}
		})
		if err != nil || pollErr != nil {
			if !cancelled.Load() {
				log.L.WithError(errors.Join(err, pollErr)).Errorf("Cannot wait for sandbox %q", p.id)
			}
			return
		}
		p.sandboxExit <- InternalErrorCode
	}()
	return nil
}
