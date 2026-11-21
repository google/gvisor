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
	var data [16]byte
	control := make([]byte, unix.CmsgSpace(4))
	n, controlLen, flags, _, err := conn.ReadMsgUnix(data[:], control)
	if err != nil {
		return -1, err
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
	monitor, pid := p.Monitor, p.pid
	events := monitor.Subscribe()
	p.cancelSandboxExit = func() { monitor.Unsubscribe(events) }
	p.sandboxExit = make(chan int, 1)
	go func() {
		defer close(p.sandboxExit)
		defer monitor.Unsubscribe(events)
		defer file.Close()
		// Inspect after subscribing so an earlier exit cannot be missed.
		for {
			poll := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}}
			n, err := unix.Poll(poll, 0)
			if err == unix.EINTR {
				continue
			}
			if err != nil {
				log.L.WithError(err).Errorf("Cannot inspect sandbox %q", p.id)
				return
			}
			if n != 0 {
				p.sandboxExit <- InternalErrorCode
				return
			}
			// PID events only wake the identity check; they do not prove death.
			for {
				e, ok := <-events
				if !ok {
					return
				}
				if e.Pid == pid {
					break
				}
			}
		}
	}()
	return nil
}
