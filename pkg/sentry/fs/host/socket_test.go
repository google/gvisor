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

package host

import (
	"reflect"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/fdnotifier"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
	"gvisor.dev/gvisor/pkg/sentry/socket"
	"gvisor.dev/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

var (
	// Make sure that ConnectedEndpoint implements transport.ConnectedEndpoint.
	_ = transport.ConnectedEndpoint(new(ConnectedEndpoint))

	// Make sure that ConnectedEndpoint implements transport.Receiver.
	_ = transport.Receiver(new(ConnectedEndpoint))
)

func getFl(fd int) (uint32, error) {
	fl, _, err := unix.RawSyscall(unix.SYS_FCNTL, uintptr(fd), unix.F_GETFL, 0)
	if err == 0 {
		return uint32(fl), nil
	}
	return 0, err
}

func TestSocketIsBlocking(t *testing.T) {
	// Using socketpair here because it's already connected.
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("host socket creation failed: %v", err)
	}

	fl, err := getFl(pair[0])
	if err != nil {
		t.Fatalf("getFl: fcntl(%v, GETFL) => %v", pair[0], err)
	}
	if fl&unix.O_NONBLOCK == unix.O_NONBLOCK {
		t.Fatalf("Expected socket %v to be blocking", pair[0])
	}
	if fl, err = getFl(pair[1]); err != nil {
		t.Fatalf("getFl: fcntl(%v, GETFL) => %v", pair[1], err)
	}
	if fl&unix.O_NONBLOCK == unix.O_NONBLOCK {
		t.Fatalf("Expected socket %v to be blocking", pair[1])
	}
	ctx := contexttest.Context(t)
	sock, err := newSocket(ctx, pair[0], false)
	if err != nil {
		t.Fatalf("newSocket(%v) failed => %v", pair[0], err)
	}
	defer sock.DecRef(ctx)
	// Test that the socket now is non-blocking.
	if fl, err = getFl(pair[0]); err != nil {
		t.Fatalf("getFl: fcntl(%v, GETFL) => %v", pair[0], err)
	}
	if fl&unix.O_NONBLOCK != unix.O_NONBLOCK {
		t.Errorf("Expected socket %v to have become non-blocking", pair[0])
	}
	if fl, err = getFl(pair[1]); err != nil {
		t.Fatalf("getFl: fcntl(%v, GETFL) => %v", pair[1], err)
	}
	if fl&unix.O_NONBLOCK == unix.O_NONBLOCK {
		t.Errorf("Did not expect socket %v to become non-blocking", pair[1])
	}
}

func TestSocketWritev(t *testing.T) {
	// Using socketpair here because it's already connected.
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("host socket creation failed: %v", err)
	}
	ctx := contexttest.Context(t)
	socket, err := newSocket(ctx, pair[0], false)
	if err != nil {
		t.Fatalf("newSocket(%v) => %v", pair[0], err)
	}
	defer socket.DecRef(ctx)
	buf := []byte("hello world\n")
	n, err := socket.Writev(contexttest.Context(t), usermem.BytesIOSequence(buf))
	if err != nil {
		t.Fatalf("socket writev failed: %v", err)
	}

	if n != int64(len(buf)) {
		t.Fatalf("socket writev wrote incorrect bytes: %d", n)
	}
}

func TestSocketWritevLen0(t *testing.T) {
	// Using socketpair here because it's already connected.
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("host socket creation failed: %v", err)
	}
	ctx := contexttest.Context(t)
	socket, err := newSocket(ctx, pair[0], false)
	if err != nil {
		t.Fatalf("newSocket(%v) => %v", pair[0], err)
	}
	defer socket.DecRef(ctx)
	n, err := socket.Writev(contexttest.Context(t), usermem.BytesIOSequence(nil))
	if err != nil {
		t.Fatalf("socket writev failed: %v", err)
	}

	if n != 0 {
		t.Fatalf("socket writev wrote incorrect bytes: %d", n)
	}
}

func TestSocketSendMsgLen0(t *testing.T) {
	// Using socketpair here because it's already connected.
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("host socket creation failed: %v", err)
	}
	ctx := contexttest.Context(t)
	sfile, err := newSocket(ctx, pair[0], false)
	if err != nil {
		t.Fatalf("newSocket(%v) => %v", pair[0], err)
	}
	defer sfile.DecRef(ctx)

	s := sfile.FileOperations.(socket.Socket)
	n, terr := s.SendMsg(nil, usermem.BytesIOSequence(nil), []byte{}, 0, false, ktime.Time{}, socket.ControlMessages{})
	if n != 0 {
		t.Fatalf("socket sendmsg() failed: %v wrote: %d", terr, n)
	}

	if terr != nil {
		t.Fatalf("socket sendmsg() failed: %v", terr)
	}
}

func TestListen(t *testing.T) {
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0) => %v", err)
	}
	ctx := contexttest.Context(t)
	sfile1, err := newSocket(ctx, pair[0], false)
	if err != nil {
		t.Fatalf("newSocket(%v) => %v", pair[0], err)
	}
	defer sfile1.DecRef(ctx)
	socket1 := sfile1.FileOperations.(socket.Socket)

	sfile2, err := newSocket(ctx, pair[1], false)
	if err != nil {
		t.Fatalf("newSocket(%v) => %v", pair[1], err)
	}
	defer sfile2.DecRef(ctx)
	socket2 := sfile2.FileOperations.(socket.Socket)

	// Socketpairs can not be listened to.
	if err := socket1.Listen(nil, 64); err != syserr.ErrInvalidEndpointState {
		t.Fatalf("socket1.Listen(nil, 64) => %v, want syserr.ErrInvalidEndpointState", err)
	}
	if err := socket2.Listen(nil, 64); err != syserr.ErrInvalidEndpointState {
		t.Fatalf("socket2.Listen(nil, 64) => %v, want syserr.ErrInvalidEndpointState", err)
	}

	// Create a Unix socket, do not bind it.
	sock, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0) => %v", err)
	}
	sfile3, err := newSocket(ctx, sock, false)
	if err != nil {
		t.Fatalf("newSocket(%v) => %v", sock, err)
	}
	defer sfile3.DecRef(ctx)
	socket3 := sfile3.FileOperations.(socket.Socket)

	// This socket is not bound so we can't listen on it.
	if err := socket3.Listen(nil, 64); err != syserr.ErrInvalidEndpointState {
		t.Fatalf("socket3.Listen(nil, 64) => %v, want syserr.ErrInvalidEndpointState", err)
	}
}

func TestPasscred(t *testing.T) {
	e := &ConnectedEndpoint{}
	if got, want := e.Passcred(), false; got != want {
		t.Errorf("Got %#v.Passcred() = %t, want = %t", e, got, want)
	}
}

func TestGetLocalAddress(t *testing.T) {
	e := &ConnectedEndpoint{path: "foo"}
	want := tcpip.FullAddress{Addr: tcpip.Address("foo")}
	if got, err := e.GetLocalAddress(); err != nil || got != want {
		t.Errorf("Got %#v.GetLocalAddress() = %#v, %v, want = %#v, %v", e, got, err, want, nil)
	}
}

func TestQueuedSize(t *testing.T) {
	e := &ConnectedEndpoint{}
	tests := []struct {
		name string
		f    func() int64
	}{
		{"SendQueuedSize", e.SendQueuedSize},
		{"RecvQueuedSize", e.RecvQueuedSize},
	}

	for _, test := range tests {
		if got, want := test.f(), int64(-1); got != want {
			t.Errorf("Got %#v.%s() = %d, want = %d", e, test.name, got, want)
		}
	}
}

func TestRelease(t *testing.T) {
	f, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal("Creating socket:", err)
	}
	c := &ConnectedEndpoint{queue: &waiter.Queue{}, file: fd.New(f)}
	want := &ConnectedEndpoint{queue: c.queue}
	ctx := contexttest.Context(t)
	want.ref.DecRef(ctx)
	fdnotifier.AddFD(int32(c.file.FD()), nil)
	c.Release(ctx)
	if !reflect.DeepEqual(c, want) {
		t.Errorf("got = %#v, want = %#v", c, want)
	}
}
