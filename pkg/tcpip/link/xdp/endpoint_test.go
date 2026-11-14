// Copyright 2024 The gVisor Authors.
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
package xdp

import (
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/stopfd"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func TestSetAddress(t *testing.T) {
	ep := &endpoint{
		addr: "xyz",
	}
	addrs := []tcpip.LinkAddress{"abc", "def"}
	for _, addr := range addrs {
		ep.SetLinkAddress(addr)

		if want, v := addr, ep.LinkAddress(); want != v {
			t.Errorf("LinkAddress() = %v, want %v", v, want)
		}
	}
}

type fakeNetworkDispatcher struct{}

func (*fakeNetworkDispatcher) DeliverNetworkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {
}

func (*fakeNetworkDispatcher) DeliverLinkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {}

// TestReattachAfterDetach checks that an endpoint can be reattached after
// detaching. It polls a socketpair that never becomes readable, since an
// AF_XDP socket needs privileges.
func TestReattachAfterDetach(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		t.Fatalf("Socketpair = %v", err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	stopFD, err := stopfd.New()
	if err != nil {
		t.Fatalf("stopfd.New = %v", err)
	}
	exited := make(chan struct{}, 1)
	ep := &endpoint{
		fd:     fds[0],
		stopFD: stopFD,
		closed: func(tcpip.Error) { exited <- struct{}{} },
	}
	defer ep.Close()

	for i := 0; i < 3; i++ {
		ep.Attach(&fakeNetworkDispatcher{})
		select {
		case <-exited:
			t.Fatalf("attachment %d: dispatch loop exited while attached", i)
		case <-time.After(100 * time.Millisecond):
		}

		detached := make(chan struct{})
		go func() {
			ep.Attach(nil)
			close(detached)
		}()
		select {
		case <-detached:
		case <-time.After(10 * time.Second):
			t.Fatalf("attachment %d: Attach(nil) did not return", i)
		}
		select {
		case <-exited:
		default:
			t.Fatalf("attachment %d: dispatch loop still running after Attach(nil)", i)
		}
	}
}
