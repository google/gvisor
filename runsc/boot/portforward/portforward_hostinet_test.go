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
	"fmt"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sync/errgroup"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
)

func TestLocalHostSocket(t *testing.T) {
	ctx := contexttest.Context(t)
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
			t.Fatalf("could not accept connection: %v", err)
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
		sock, err := NewHostInetConn(uint16(port))
		if err != nil {
			t.Fatalf("could not create local host socket: %v", err)
		}
		for i := 0; i < len(clientData); {
			n, err := sock.Write(ctx, clientData[i:], nil)
			if err != nil {
				return fmt.Errorf("could not write to local host socket: %v", err)
			}
			i += n
		}

		data := make([]byte, 1024)
		dataLen := 0
		for dataLen < len(serverData) {
			n, err := sock.Read(ctx, data[dataLen:], nil)
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

type netConnMockEndpoint struct {
	conn net.Conn
	mu   sync.Mutex
}

// read implements portforwarderTestHarness.read.
func (nc *netConnMockEndpoint) read(n int) ([]byte, error) {
	nc.mu.Lock()
	defer nc.mu.Unlock()

	buf := make([]byte, n)
	nc.conn.SetReadDeadline(time.Now().Add(time.Millisecond * 500))
	res, err := nc.conn.Read(buf)
	if err != nil && strings.Contains(err.Error(), "timeout") {
		return nil, linuxerr.ErrWouldBlock
	}
	return buf[:res], err
}

// write implements portforwarderTestHarness write.
func (nc *netConnMockEndpoint) write(buf []byte) (int, error) {
	nc.mu.Lock()
	defer nc.mu.Unlock()
	written := 0
	for {
		n, err := nc.conn.Write(buf[written:])
		if err != nil && !linuxerr.Equals(linuxerr.ErrWouldBlock, err) {
			return n, err
		}
		written += n
		if written >= len(buf) {
			return written, nil
		}
	}
}

func TestHostInetProxy(t *testing.T) {
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
			doHostinetTest(t, tc.name, tc.requests)
		})
	}
}

func doHostinetTest(t *testing.T, name string, requests map[string]string) {
	ctx := context.Background()
	appEndpoint := newMockApplicationFDImpl()
	client, err := newMockFileDescription(ctx, appEndpoint)
	if err != nil {
		t.Fatalf("newMockFileDescription: %v", err)
	}

	l, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("net.Listen failed: %v", err)
	}
	defer l.Close()
	port := uint16(l.Addr().(*net.TCPAddr).Port)
	sock, err := NewHostInetConn(port)
	if err != nil {
		t.Fatalf("could not create local host socket: %v", err)
	}

	proxy := NewProxy(ProxyPair{To: sock, From: &fileDescriptionConn{file: client}}, name)

	proxy.Start(ctx)

	shim, err := l.Accept()
	if err != nil {
		t.Fatalf("could not accept shim connection: %v", err)
	}
	defer shim.Close()
	harness := portforwarderTestHarness{
		app:  appEndpoint,
		shim: &netConnMockEndpoint{conn: shim},
	}

	for req, resp := range requests {
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
