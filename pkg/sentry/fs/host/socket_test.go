// Copyright 2018 Google LLC
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
	"syscall"
	"testing"

	"gvisor.googlesource.com/gvisor/pkg/fd"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context/contexttest"
	ktime "gvisor.googlesource.com/gvisor/pkg/sentry/kernel/time"
	"gvisor.googlesource.com/gvisor/pkg/sentry/socket"
	"gvisor.googlesource.com/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserr"
	"gvisor.googlesource.com/gvisor/pkg/tcpip"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
	"gvisor.googlesource.com/gvisor/pkg/waiter/fdnotifier"
)

var (
	// Make sure that ConnectedEndpoint implements transport.ConnectedEndpoint.
	_ = transport.ConnectedEndpoint(new(ConnectedEndpoint))

	// Make sure that ConnectedEndpoint implements transport.Receiver.
	_ = transport.Receiver(new(ConnectedEndpoint))
)

func getFl(fd int) (uint32, error) {
	fl, _, err := syscall.RawSyscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFL, 0)
	if err == 0 {
		return uint32(fl), nil
	}
	return 0, err
}

func TestSocketIsBlocking(t *testing.T) {
	// Using socketpair here because it's already connected.
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("host socket creation failed: %v", err)
	}

	fl, err := getFl(pair[0])
	if err != nil {
		t.Fatalf("getFl: fcntl(%v, GETFL) => %v", pair[0], err)
	}
	if fl&syscall.O_NONBLOCK == syscall.O_NONBLOCK {
		t.Fatalf("Expected socket %v to be blocking", pair[0])
	}
	if fl, err = getFl(pair[1]); err != nil {
		t.Fatalf("getFl: fcntl(%v, GETFL) => %v", pair[1], err)
	}
	if fl&syscall.O_NONBLOCK == syscall.O_NONBLOCK {
		t.Fatalf("Expected socket %v to be blocking", pair[1])
	}
	sock, err := newSocket(contexttest.Context(t), pair[0], false)
	if err != nil {
		t.Fatalf("newSocket(%v) failed => %v", pair[0], err)
	}
	defer sock.DecRef()
	// Test that the socket now is non-blocking.
	if fl, err = getFl(pair[0]); err != nil {
		t.Fatalf("getFl: fcntl(%v, GETFL) => %v", pair[0], err)
	}
	if fl&syscall.O_NONBLOCK != syscall.O_NONBLOCK {
		t.Errorf("Expected socket %v to have become non-blocking", pair[0])
	}
	if fl, err = getFl(pair[1]); err != nil {
		t.Fatalf("getFl: fcntl(%v, GETFL) => %v", pair[1], err)
	}
	if fl&syscall.O_NONBLOCK == syscall.O_NONBLOCK {
		t.Errorf("Did not expect socket %v to become non-blocking", pair[1])
	}
}

func TestSocketWritev(t *testing.T) {
	// Using socketpair here because it's already connected.
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("host socket creation failed: %v", err)
	}
	socket, err := newSocket(contexttest.Context(t), pair[0], false)
	if err != nil {
		t.Fatalf("newSocket(%v) => %v", pair[0], err)
	}
	defer socket.DecRef()
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
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("host socket creation failed: %v", err)
	}
	socket, err := newSocket(contexttest.Context(t), pair[0], false)
	if err != nil {
		t.Fatalf("newSocket(%v) => %v", pair[0], err)
	}
	defer socket.DecRef()
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
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("host socket creation failed: %v", err)
	}
	sfile, err := newSocket(contexttest.Context(t), pair[0], false)
	if err != nil {
		t.Fatalf("newSocket(%v) => %v", pair[0], err)
	}
	defer sfile.DecRef()

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
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0) => %v", err)
	}
	sfile1, err := newSocket(contexttest.Context(t), pair[0], false)
	if err != nil {
		t.Fatalf("newSocket(%v) => %v", pair[0], err)
	}
	defer sfile1.DecRef()
	socket1 := sfile1.FileOperations.(socket.Socket)

	sfile2, err := newSocket(contexttest.Context(t), pair[1], false)
	if err != nil {
		t.Fatalf("newSocket(%v) => %v", pair[1], err)
	}
	defer sfile2.DecRef()
	socket2 := sfile2.FileOperations.(socket.Socket)

	// Socketpairs can not be listened to.
	if err := socket1.Listen(nil, 64); err != syserr.ErrInvalidEndpointState {
		t.Fatalf("socket1.Listen(nil, 64) => %v, want syserr.ErrInvalidEndpointState", err)
	}
	if err := socket2.Listen(nil, 64); err != syserr.ErrInvalidEndpointState {
		t.Fatalf("socket2.Listen(nil, 64) => %v, want syserr.ErrInvalidEndpointState", err)
	}

	// Create a Unix socket, do not bind it.
	sock, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0) => %v", err)
	}
	sfile3, err := newSocket(contexttest.Context(t), sock, false)
	if err != nil {
		t.Fatalf("newSocket(%v) => %v", sock, err)
	}
	defer sfile3.DecRef()
	socket3 := sfile3.FileOperations.(socket.Socket)

	// This socket is not bound so we can't listen on it.
	if err := socket3.Listen(nil, 64); err != syserr.ErrInvalidEndpointState {
		t.Fatalf("socket3.Listen(nil, 64) => %v, want syserr.ErrInvalidEndpointState", err)
	}
}

func TestSend(t *testing.T) {
	e := ConnectedEndpoint{writeClosed: true}
	if _, _, err := e.Send(nil, transport.ControlMessages{}, tcpip.FullAddress{}); err != syserr.ErrClosedForSend {
		t.Errorf("Got %#v.Send() = %v, want = %v", e, err, syserr.ErrClosedForSend)
	}
}

func TestRecv(t *testing.T) {
	e := ConnectedEndpoint{readClosed: true}
	if _, _, _, _, _, err := e.Recv(nil, false, 0, false); err != syserr.ErrClosedForReceive {
		t.Errorf("Got %#v.Recv() = %v, want = %v", e, err, syserr.ErrClosedForReceive)
	}
}

func TestPasscred(t *testing.T) {
	e := ConnectedEndpoint{}
	if got, want := e.Passcred(), false; got != want {
		t.Errorf("Got %#v.Passcred() = %t, want = %t", e, got, want)
	}
}

func TestGetLocalAddress(t *testing.T) {
	e := ConnectedEndpoint{path: "foo"}
	want := tcpip.FullAddress{Addr: tcpip.Address("foo")}
	if got, err := e.GetLocalAddress(); err != nil || got != want {
		t.Errorf("Got %#v.GetLocalAddress() = %#v, %v, want = %#v, %v", e, got, err, want, nil)
	}
}

func TestQueuedSize(t *testing.T) {
	e := ConnectedEndpoint{}
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

func TestReadable(t *testing.T) {
	e := ConnectedEndpoint{readClosed: true}
	if got, want := e.Readable(), true; got != want {
		t.Errorf("Got %#v.Readable() = %t, want = %t", e, got, want)
	}
}

func TestWritable(t *testing.T) {
	e := ConnectedEndpoint{writeClosed: true}
	if got, want := e.Writable(), true; got != want {
		t.Errorf("Got %#v.Writable() = %t, want = %t", e, got, want)
	}
}

func TestRelease(t *testing.T) {
	f, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal("Creating socket:", err)
	}
	c := &ConnectedEndpoint{queue: &waiter.Queue{}, file: fd.New(f)}
	want := &ConnectedEndpoint{queue: c.queue}
	want.ref.DecRef()
	fdnotifier.AddFD(int32(c.file.FD()), nil)
	c.Release()
	if !reflect.DeepEqual(c, want) {
		t.Errorf("got = %#v, want = %#v", c, want)
	}
}

func TestClose(t *testing.T) {
	type testCase struct {
		name  string
		cep   *ConnectedEndpoint
		addFD bool
		f     func()
		want  *ConnectedEndpoint
	}

	var tests []testCase

	// nil is the value used by ConnectedEndpoint to indicate a closed file.
	// Non-nil files are used to check if the file gets closed.

	f, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal("Creating socket:", err)
	}
	c := &ConnectedEndpoint{queue: &waiter.Queue{}, file: fd.New(f)}
	tests = append(tests, testCase{
		name:  "First CloseRecv",
		cep:   c,
		addFD: false,
		f:     c.CloseRecv,
		want:  &ConnectedEndpoint{queue: c.queue, file: c.file, readClosed: true},
	})

	f, err = syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal("Creating socket:", err)
	}
	c = &ConnectedEndpoint{queue: &waiter.Queue{}, file: fd.New(f), readClosed: true}
	tests = append(tests, testCase{
		name:  "Second CloseRecv",
		cep:   c,
		addFD: false,
		f:     c.CloseRecv,
		want:  &ConnectedEndpoint{queue: c.queue, file: c.file, readClosed: true},
	})

	f, err = syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal("Creating socket:", err)
	}
	c = &ConnectedEndpoint{queue: &waiter.Queue{}, file: fd.New(f)}
	tests = append(tests, testCase{
		name:  "First CloseSend",
		cep:   c,
		addFD: false,
		f:     c.CloseSend,
		want:  &ConnectedEndpoint{queue: c.queue, file: c.file, writeClosed: true},
	})

	f, err = syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal("Creating socket:", err)
	}
	c = &ConnectedEndpoint{queue: &waiter.Queue{}, file: fd.New(f), writeClosed: true}
	tests = append(tests, testCase{
		name:  "Second CloseSend",
		cep:   c,
		addFD: false,
		f:     c.CloseSend,
		want:  &ConnectedEndpoint{queue: c.queue, file: c.file, writeClosed: true},
	})

	f, err = syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal("Creating socket:", err)
	}
	c = &ConnectedEndpoint{queue: &waiter.Queue{}, file: fd.New(f), writeClosed: true}
	tests = append(tests, testCase{
		name:  "CloseSend then CloseRecv",
		cep:   c,
		addFD: true,
		f:     c.CloseRecv,
		want:  &ConnectedEndpoint{queue: c.queue, file: c.file, readClosed: true, writeClosed: true},
	})

	f, err = syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal("Creating socket:", err)
	}
	c = &ConnectedEndpoint{queue: &waiter.Queue{}, file: fd.New(f), readClosed: true}
	tests = append(tests, testCase{
		name:  "CloseRecv then CloseSend",
		cep:   c,
		addFD: true,
		f:     c.CloseSend,
		want:  &ConnectedEndpoint{queue: c.queue, file: c.file, readClosed: true, writeClosed: true},
	})

	f, err = syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal("Creating socket:", err)
	}
	c = &ConnectedEndpoint{queue: &waiter.Queue{}, file: fd.New(f), readClosed: true, writeClosed: true}
	tests = append(tests, testCase{
		name:  "Full close then CloseRecv",
		cep:   c,
		addFD: false,
		f:     c.CloseRecv,
		want:  &ConnectedEndpoint{queue: c.queue, file: c.file, readClosed: true, writeClosed: true},
	})

	f, err = syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal("Creating socket:", err)
	}
	c = &ConnectedEndpoint{queue: &waiter.Queue{}, file: fd.New(f), readClosed: true, writeClosed: true}
	tests = append(tests, testCase{
		name:  "Full close then CloseSend",
		cep:   c,
		addFD: false,
		f:     c.CloseSend,
		want:  &ConnectedEndpoint{queue: c.queue, file: c.file, readClosed: true, writeClosed: true},
	})

	for _, test := range tests {
		if test.addFD {
			fdnotifier.AddFD(int32(test.cep.file.FD()), nil)
		}
		if test.f(); !reflect.DeepEqual(test.cep, test.want) {
			t.Errorf("%s: got = %#v, want = %#v", test.name, test.cep, test.want)
		}
	}
}
