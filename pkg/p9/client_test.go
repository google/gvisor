// Copyright 2018 Google Inc.
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
	"syscall"
	"testing"

	"gvisor.googlesource.com/gvisor/pkg/unet"
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
	c, err := NewClient(clientSocket, 1024*1024 /* 1M message size */, HighestVersionString())
	if err != nil {
		t.Fatalf("got %v, expected nil", err)
	}

	// Check a bogus version string.
	if err := c.sendRecv(&Tversion{Version: "notokay", MSize: 1024 * 1024}, &Rversion{}); err != syscall.EINVAL {
		t.Errorf("got %v expected %v", err, syscall.EINVAL)
	}

	// Check a bogus version number.
	if err := c.sendRecv(&Tversion{Version: "9P1000.L", MSize: 1024 * 1024}, &Rversion{}); err != syscall.EINVAL {
		t.Errorf("got %v expected %v", err, syscall.EINVAL)
	}

	// Check a too high version number.
	if err := c.sendRecv(&Tversion{Version: versionString(highestSupportedVersion + 1), MSize: 1024 * 1024}, &Rversion{}); err != syscall.EAGAIN {
		t.Errorf("got %v expected %v", err, syscall.EAGAIN)
	}

	// Check an invalid MSize.
	if err := c.sendRecv(&Tversion{Version: versionString(highestSupportedVersion), MSize: 0}, &Rversion{}); err != syscall.EINVAL {
		t.Errorf("got %v expected %v", err, syscall.EINVAL)
	}
}
