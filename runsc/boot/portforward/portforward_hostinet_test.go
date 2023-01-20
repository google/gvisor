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
	"testing"

	"golang.org/x/sync/errgroup"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
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

type netConnMockEndpoint struct {
	conn net.Conn
}

// read implements portforwarderTestHarness.read.
func (nc *netConnMockEndpoint) read(n int) ([]byte, error) {
	buf := make([]byte, n)
	n, err := nc.conn.Read(buf)
	return buf[:n], err
}

// write implements portforwarderTestHarness write.
func (nc *netConnMockEndpoint) write(buf []byte) (int, error) {
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

func TestHostinetPortForwardConn(t *testing.T) {
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
			doHostinetTest(t, tc.requests)
		})
	}
}

func doHostinetTest(t *testing.T, requests map[string]string) {
	ctx := contexttest.Context(t)
	appEndpoint := &mockApplicationFDImpl{}
	defer appEndpoint.Release(ctx)
	client, err := newMockFileDescription(ctx, appEndpoint)
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

	harness := portforwarderTestHarness{
		app:  appEndpoint,
		shim: &netConnMockEndpoint{conn},
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
