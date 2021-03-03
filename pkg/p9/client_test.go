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

package p9

import (
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/unet"
)

// TestVersion tests the version negotiation.
func TestVersion(t *testing.T) {
	// First, create a new server and connection.
	serverSocket, clientSocket, err := unet.SocketPair(false)
	if err != nil {
		t.Fatalf("socketpair got err %v expected nil", err)
	}
	defer clientSocket.Close()

	// Create a new server and client.
	s := NewServer(nil)
	go s.Handle(serverSocket)

	// NewClient does a Tversion exchange, so this is our test for success.
	c, err := NewClient(clientSocket, DefaultMessageSize, HighestVersionString())
	if err != nil {
		t.Fatalf("got %v, expected nil", err)
	}

	// Check a bogus version string.
	if err := c.sendRecv(&Tversion{Version: "notokay", MSize: DefaultMessageSize}, &Rversion{}); err != unix.EINVAL {
		t.Errorf("got %v expected %v", err, unix.EINVAL)
	}

	// Check a bogus version number.
	if err := c.sendRecv(&Tversion{Version: "9P1000.L", MSize: DefaultMessageSize}, &Rversion{}); err != unix.EINVAL {
		t.Errorf("got %v expected %v", err, unix.EINVAL)
	}

	// Check a too high version number.
	if err := c.sendRecv(&Tversion{Version: versionString(highestSupportedVersion + 1), MSize: DefaultMessageSize}, &Rversion{}); err != unix.EAGAIN {
		t.Errorf("got %v expected %v", err, unix.EAGAIN)
	}

	// Check an invalid MSize.
	if err := c.sendRecv(&Tversion{Version: versionString(highestSupportedVersion), MSize: 0}, &Rversion{}); err != unix.EINVAL {
		t.Errorf("got %v expected %v", err, unix.EINVAL)
	}
}

func benchmarkSendRecv(b *testing.B, fn func(c *Client) func(message, message) error) {
	b.ReportAllocs()

	// See above.
	serverSocket, clientSocket, err := unet.SocketPair(false)
	if err != nil {
		b.Fatalf("socketpair got err %v expected nil", err)
	}
	defer clientSocket.Close()

	// See above.
	s := NewServer(nil)
	go s.Handle(serverSocket)

	// See above.
	c, err := NewClient(clientSocket, DefaultMessageSize, HighestVersionString())
	if err != nil {
		b.Fatalf("got %v, expected nil", err)
	}

	// Initialize messages.
	sendRecv := fn(c)
	tversion := &Tversion{
		Version: versionString(highestSupportedVersion),
		MSize:   DefaultMessageSize,
	}
	rversion := new(Rversion)

	// Run in a loop.
	for i := 0; i < b.N; i++ {
		if err := sendRecv(tversion, rversion); err != nil {
			b.Fatalf("got unexpected err: %v", err)
		}
	}
}

func BenchmarkSendRecvLegacy(b *testing.B) {
	benchmarkSendRecv(b, func(c *Client) func(message, message) error {
		return func(t message, r message) error {
			_, err := c.sendRecvLegacy(t, r)
			return err
		}
	})
}

func BenchmarkSendRecvChannel(b *testing.B) {
	benchmarkSendRecv(b, func(c *Client) func(message, message) error { return c.sendRecvChannel })
}
