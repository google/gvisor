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

package server_test

import (
	"errors"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
	"gvisor.dev/gvisor/pkg/sentry/seccheck/sinks/remote/test"
	"gvisor.dev/gvisor/pkg/sentry/seccheck/sinks/remote/wire"
)

// connect connects to the server and performs the handshake.
func connect(t *testing.T, endpoint string) int {
	t.Helper()
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	if err := unix.Connect(fd, &unix.SockaddrUnix{Name: endpoint}); err != nil {
		t.Fatalf("connect(%q): %v", endpoint, err)
	}
	hs, err := proto.Marshal(&pb.Handshake{Version: wire.CurrentVersion})
	if err != nil {
		t.Fatalf("marshal handshake: %v", err)
	}
	if _, err := unix.Write(fd, hs); err != nil {
		t.Fatalf("write handshake: %v", err)
	}
	var in [1024]byte
	if _, err := unix.Read(fd, in[:]); err != nil {
		t.Fatalf("read handshake: %v", err)
	}
	return fd
}

// message returns a well-formed message with the given payload.
func message(payload []byte) []byte {
	hdr := wire.Header{
		HeaderSize:  uint16(wire.HeaderStructSize),
		MessageType: uint16(pb.MessageType_MESSAGE_CONTAINER_START),
	}
	out := make([]byte, wire.HeaderStructSize+len(payload))
	hdr.MarshalUnsafe(out)
	copy(out[wire.HeaderStructSize:], payload)
	return out
}

// waitForCount waits for the server to have received want points.
func waitForCount(t *testing.T, s *test.Server, want int) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		if s.Count() >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("server got %d points, want %d", s.Count(), want)
}

func TestMalformedMessagesAreDropped(t *testing.T) {
	s, err := test.NewServer()
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer s.Close()
	fd := connect(t, s.Endpoint)

	// A message smaller than the header.
	if _, err := unix.Write(fd, []byte{1}); err != nil {
		t.Fatalf("write: %v", err)
	}
	// A header that claims to be larger than the message.
	bad := message(nil)
	bad[0] = 0xff
	if _, err := unix.Write(fd, bad); err != nil {
		t.Fatalf("write: %v", err)
	}
	// A message larger than the server's buffer. The kernel may refuse to send
	// it if the socket's send buffer limit is lower.
	big := message(make([]byte, 1024*1024))
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, 4*len(big)); err != nil {
		t.Fatalf("setsockopt(SO_SNDBUF): %v", err)
	}
	if _, err := unix.Write(fd, big); err != nil && !errors.Is(err, unix.EMSGSIZE) {
		t.Fatalf("write: %v", err)
	} else if err != nil {
		t.Logf("Skipping oversized message, the kernel refused to send it: %v", err)
	}

	// The connection still works, and only the valid message is recorded.
	if _, err := unix.Write(fd, message([]byte("ok"))); err != nil {
		t.Fatalf("write: %v", err)
	}
	waitForCount(t, s, 1)
	points := s.GetPoints()
	if len(points) != 1 || string(points[0].Msg) != "ok" {
		t.Errorf("server got points %+v, want only the valid message", points)
	}
}
