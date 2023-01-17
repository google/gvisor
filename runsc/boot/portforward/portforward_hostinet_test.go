// Copyright 2023 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package portforward

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"reflect"
	"sync"
	"testing"

	"golang.org/x/sync/errgroup"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

func TestLocalHostSocket(t *testing.T) {

	clientData := append(
		[]byte("do what must be done\n"),
		[]byte("do not hesitate\n")...,
	)

	serverData := append(
		[]byte("commander cody...the time has come\n"),
		[]byte("execute order 66\n")...,
	)

	l, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("net.Listen failed: %v", err)
	}
	defer l.Close()

	port := l.Addr().(*net.TCPAddr).Port

	var g errgroup.Group

	g.Go(func() error {
		conn, err := l.Accept()
		if err != nil {
			return fmt.Errorf("could not accept connection: %v", err)
		}
		defer conn.Close()

		data := make([]byte, 1024)
		recLen, err := conn.Read(data)
		if err != nil {
			return fmt.Errorf("could not read data: %v", err)
		}

		if !reflect.DeepEqual(data[:recLen], clientData) {
			return fmt.Errorf("server mismatch data recieved: got: %s want: %s", data[:recLen], clientData)
		}

		sentLen, err := conn.Write(serverData)
		if err != nil {
			return fmt.Errorf("could not write data: %v", err)
		}

		if sentLen != len(serverData) {
			return fmt.Errorf("server mismatch data sent: got: %d want: %d", sentLen, len(serverData))
		}

		return nil
	})

	g.Go(func() error {
		sock, err := newLocalHostSocket()
		if err != nil {
			return fmt.Errorf("could not create local host socket: %v", err)
		}
		defer sock.Close()
		if err := sock.Connect(uint16(port)); err != nil {
			return fmt.Errorf("could not connect to local host socket: %v", err)
		}
		for i := 0; i < len(clientData); {
			n, err := sock.Write(clientData[i:])
			if err != nil {
				return fmt.Errorf("could not write to local host socket: %v", err)
			}
			i += n
		}

		data := make([]byte, 1024)
		dataLen := 0
		for dataLen < len(serverData) {
			n, err := sock.Read(data[dataLen:])
			if err != nil {
				t.Fatalf("could not read from local host socket: %v", err)
			}
			dataLen += n
		}

		if !reflect.DeepEqual(data[:dataLen], serverData) {
			return fmt.Errorf("server mismatch data received: got: %s want: %s", data[:dataLen], clientData)
		}
		return nil
	})

	if err := g.Wait(); err != nil {
		t.Fatal(err)
	}
}

func newMockSocketPair() (*mockEndpoint, *mockEndpoint) {
	client := &mockEndpoint{}
	server := &mockEndpoint{other: client}
	client.other = server
	return client, server
}

type mockEndpoint struct {
	vfs.FileDescriptionDefaultImpl
	vfs.NoLockFD
	vfs.DentryMetadataFileDescriptionImpl
	other    *mockEndpoint
	readBuf  bytes.Buffer
	mu       sync.Mutex
	released bool
	queue    waiter.Queue
}

var _ vfs.FileDescriptionImpl = (*mockEndpoint)(nil)

// Read implements vfs.FileDescriptionImpl.Read details for the parent mockFileDescription.
func (s *mockEndpoint) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.released {
		return 0, io.EOF
	}
	if s.readBuf.Len() == 0 {
		return 0, linuxerr.ErrWouldBlock
	}
	buf := s.readBuf.Next(s.readBuf.Len())
	n, err := dst.CopyOut(ctx, buf)
	s.queue.Notify(waiter.WritableEvents)
	return int64(n), err
}

// Write implements vfs.FileDescriptionImpl.Write details for the parent mockFileDescription.
func (s *mockEndpoint) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	return s.other.write(ctx, src, opts)
}

func (s *mockEndpoint) write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.released {
		return 0, io.EOF
	}
	buf := make([]byte, src.NumBytes())
	n, err := src.CopyIn(ctx, buf)
	if err != nil {
		return 0, err
	}
	n, err = s.readBuf.Write(buf[:n])
	s.queue.Notify(waiter.ReadableEvents)
	return int64(n), err
}

func (s *mockEndpoint) IsReadable() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.released {
		return false
	}
	return s.readBuf.Len() > 0
}

func (s *mockEndpoint) IsWritable() bool {
	return s.other.isWritable()
}

func (s *mockEndpoint) isWritable() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.released
}

// EventRegister implements vfs.FileDescriptionImpl.EventRegister details for the parent mockFileDescription.
func (s *mockEndpoint) EventRegister(we *waiter.Entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queue.EventRegister(we)
	return nil
}

// EventUnregister implements vfs.FileDescriptionImpl.Unregister details for the parent mockFileDescription.
func (s *mockEndpoint) EventUnregister(we *waiter.Entry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queue.EventUnregister(we)
}

// Release implements vfs.FileDescriptionImpl.Release details for the parent mockFileDescription.
func (s *mockEndpoint) Release(context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queue.Notify(waiter.ReadableEvents)
	s.released = true
}

var responses = map[string]string{
	"PING": "PONG",
	"DING": "DONG",
	"TING": "TONG",
}

func TestHostinetPortForwardConn(t *testing.T) {
	ctx := contexttest.Context(t)
	clientSock, server := newMockSocketPair()
	defer server.Release(ctx)
	client, err := newMockFileDescription(ctx, clientSock)
	if err != nil {
		t.Fatalf("newMockFileDescription failed: %v", err)
	}
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("net.Listen failed: %v", err)
	}
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port
	portForwardConn, err := newHostinetPortForward(ctx, "", client, uint16(port))
	if err != nil {
		t.Fatalf("newHostinetPortForward failed: %v", err)
	}
	if err := portForwardConn.start(ctx); err != nil {
		t.Fatalf("portForwardConn.start failed: %v", err)
	}
	conn, err := l.Accept()
	if err != nil {
		t.Fatalf("l.Accept failed: %v", err)
	}
	defer conn.Close()
	buf := make([]byte, 4)
	for req, resp := range responses {

		for {
			if server.IsWritable() {
				break
			}
		}
		_, err := server.Write(ctx, usermem.BytesIOSequence([]byte(req)), vfs.WriteOptions{})
		if err != nil {
			t.Fatalf("file.Write failed: %v", err)
		}

		read := 0
		for {
			n, err := conn.Read([]byte(buf)[read:])
			if err != nil && !linuxerr.Equals(linuxerr.ErrWouldBlock, err) {
				t.Fatalf("conn.Write failed: %v", err)
			}
			read += n
			if read >= len(resp) {
				break
			}
		}

		if string(buf) != req {
			t.Fatalf("read mismatch: got: %s want: %s", string(buf), req)
		}

		written := 0
		for i := 0; i < 4; i++ {
			n, err := conn.Write([]byte(resp)[written:])
			if err != nil && !linuxerr.Equals(linuxerr.ErrWouldBlock, err) {
				t.Fatalf("conn.Write failed: %v", err)
			}
			written += n
			if written >= len(resp) {
				break
			}
		}

		for {
			if server.IsReadable() {
				break
			}
		}

		_, err = server.Read(ctx, usermem.BytesIOSequence([]byte(buf[:4])), vfs.ReadOptions{})
		if err != nil && !linuxerr.Equals(linuxerr.ErrWouldBlock, err) {
			t.Fatalf("file.Read failed: %v", err)
		}

		if string(buf) != resp {
			t.Fatalf("write mismatch: got: %s want: %s", string(buf), resp)
		}
	}
}
