// Copyright 2023 The gVisor Authors.
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

package portforward

import (
	"bytes"
	"io"
	"sync"
	"testing"

	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/waiter"
)

type baseTCPEndpointImpl struct {
	closed   bool
	readBuf  bytes.Buffer
	writeBuf bytes.Buffer
	mu       sync.Mutex
}

// read reads data from the buffer that "Write" writes to.
func (b *baseTCPEndpointImpl) read(n int) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil, io.EOF
	}
	ret := b.writeBuf.Next(n)
	return ret, nil
}

// write writes data to the read buffer that "Read" reads from.
func (b *baseTCPEndpointImpl) write(buf []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return 0, io.EOF
	}
	n, err := b.readBuf.Write(buf)
	return n, err
}

func (b *baseTCPEndpointImpl) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
}

func (b *baseTCPEndpointImpl) Read(w io.Writer, _ tcpip.ReadOptions) (tcpip.ReadResult, tcpip.Error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return tcpip.ReadResult{}, &tcpip.ErrClosedForReceive{}
	}
	buf := b.readBuf.Next(b.readBuf.Len())
	n, err := w.Write(buf)
	if err != nil {
		return tcpip.ReadResult{}, &tcpip.ErrInvalidEndpointState{}
	}
	return tcpip.ReadResult{
		Count: n,
		Total: n,
	}, nil
}

func (b *baseTCPEndpointImpl) Write(payload tcpip.Payloader, _ tcpip.WriteOptions) (int64, tcpip.Error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return 0, &tcpip.ErrClosedForSend{}
	}
	buf := make([]byte, payload.Len())
	n, err := payload.Read(buf)
	if err != nil {
		return 0, &tcpip.ErrInvalidEndpointState{}
	}
	n, err = b.writeBuf.Write(buf[:n])
	if err != nil {
		return int64(n), &tcpip.ErrConnectionRefused{}
	}
	return int64(n), nil
}

func (b *baseTCPEndpointImpl) Shutdown(shutdown tcpip.ShutdownFlags) tcpip.Error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	return nil
}

func TestNetstackProxy(t *testing.T) {
	for _, tc := range []struct {
		name     string
		requests map[string]string
	}{
		{
			name: "single",
			requests: map[string]string{
				"PING": "PONG",
			},
		},
		{
			name: "multiple",
			requests: map[string]string{
				"PING":       "PONG",
				"HELLO":      "GOODBYE",
				"IMPRESSIVE": "MOST IMPRESSIVE",
			},
		},
		{
			name: "empty",
			requests: map[string]string{
				"EMPTY":       "",
				"NOT":         "EMPTY",
				"OTHER EMPTY": "",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doNetstackTest(t, tc.name, tc.requests)
		})
	}
}

func doNetstackTest(t *testing.T, name string, responses map[string]string) {
	ctx := contexttest.Context(t)
	appEndpoint := newMockApplicationFDImpl()
	fd, err := newMockFileDescription(ctx, appEndpoint)
	if err != nil {
		t.Fatalf("newMockFileDescription: %v", err)
	}

	wq := &waiter.Queue{}
	impl := &baseTCPEndpointImpl{}
	ep := newMockTCPEndpoint(impl, wq)
	sock := &netstackConn{
		ep: ep,
		wq: wq,
	}

	proxy := NewProxy(ProxyPair{To: sock, From: &fileDescriptionConn{file: fd}}, name)
	proxy.Start(ctx)
	defer proxy.Close()

	harness := portforwarderTestHarness{
		app:  appEndpoint,
		shim: impl,
	}

	for req, resp := range responses {
		if _, err := harness.shimWrite([]byte(req)); err != nil {
			t.Fatalf("failed to write to shim: %v", err)
		}

		got, err := harness.appRead(len(req))
		if err != nil {
			t.Fatalf("failed to read from app: %v", err)
		}

		if string(got) != req {
			t.Fatalf("app mismatch: got: %s want: %s", string(got), req)
		}

		if _, err := harness.appWrite([]byte(resp)); err != nil {
			t.Fatalf("failed to write to app: %v", err)
		}

		got, err = harness.shimRead(len(resp))
		if err != nil {
			t.Fatalf("failed to read from shim: %v", err)
		}

		if string(got) != resp {
			t.Fatalf("shim mismatch: got: %s want: %s", string(got), resp)
		}
	}
}

// tcpErrImpl blocks on the first Read/Write and then throws an error afterwards.
type tcpErrImpl struct {
	mu     sync.Mutex
	reads  bool
	writes bool
}

// Read implements mockTCPEndpointImpl.Read.
func (e *tcpErrImpl) Read(w io.Writer, _ tcpip.ReadOptions) (tcpip.ReadResult, tcpip.Error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.reads {
		return tcpip.ReadResult{}, &tcpip.ErrBadLocalAddress{}
	}
	e.reads = true
	return tcpip.ReadResult{}, &tcpip.ErrWouldBlock{}
}

// Write implements mockTCPEndpointImpl.Write.
func (e *tcpErrImpl) Write(payload tcpip.Payloader, _ tcpip.WriteOptions) (int64, tcpip.Error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.writes {
		return 0, &tcpip.ErrBadLocalAddress{}
	}
	e.writes = true
	return 0, &tcpip.ErrWouldBlock{}
}

// Shutdown implements mockTCPEndpointImpl.Shutdown.
func (e *tcpErrImpl) Shutdown(shutdown tcpip.ShutdownFlags) tcpip.Error {
	return nil
}

// Close implements mockTCPEndpointImpl.Shutdown.
func (e *tcpErrImpl) Close() {}

// TestNTestNestackReadsWrites checks that reads/writes check errors from the underlying endpoint
// multiple times.
func TestNestackReadsWrites(t *testing.T) {
	ctx := contexttest.Context(t)
	wq := &waiter.Queue{}
	ep := newMockTCPEndpoint(&tcpErrImpl{}, wq)
	cancel := make(chan struct{})
	conn := netstackConn{ep: ep, wq: wq}
	defer close(cancel)
	defer conn.Close(ctx)

	_, err := conn.Read(ctx, []byte("something"), cancel)
	if err != io.EOF {
		t.Fatalf("mismatch read err: want: %v got: %v", io.EOF, err)
	}

	_, err = conn.Write(ctx, []byte("something"), cancel)
	if err != io.EOF {
		t.Fatalf("mismatch write err: want: %v got: %v", io.EOF, err)
	}
}
