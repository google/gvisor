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

package netstack_test

import (
	"testing"
	"testing/synctest"

	"gvisor.dev/gvisor/pkg/sentry/socket/netstack"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func TestDestroyNilStack(t *testing.T) {
	s := &netstack.Stack{
		Stack: nil,
	}
	// This should not panic.
	s.Destroy()
}

type blockedCloseEndpoint struct {
	*channel.Endpoint
	closing chan struct{}
	resume  chan struct{}
}

func (e *blockedCloseEndpoint) Close() {
	close(e.closing)
	<-e.resume
	e.Endpoint.Close()
}

func TestDestroyWaitsForNICs(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := netstack.NewStack(stack.New(stack.Options{}), 1)
		ep := &blockedCloseEndpoint{
			Endpoint: channel.New(1, 1500, ""),
			closing:  make(chan struct{}),
			resume:   make(chan struct{}),
		}
		if err := s.Stack.CreateNIC(1, ep); err != nil {
			t.Fatalf("CreateNIC: %s", err)
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{})
		var packets stack.PacketBufferList
		packets.PushBack(pkt)
		n, err := ep.WritePackets(packets)
		pkt.DecRef()
		if n != 1 || err != nil {
			t.Fatalf("WritePackets = (%d, %v), want (1, nil)", n, err)
		}
		done := make(chan struct{})
		go func() {
			s.Destroy()
			close(done)
		}()
		<-ep.closing
		synctest.Wait()
		select {
		case <-done:
			t.Error("Destroy returned before NIC cleanup released its packet")
		default:
		}
		close(ep.resume)
		<-done
		synctest.Wait()
		if got := ep.NumQueued(); got != 0 {
			t.Errorf("NumQueued after Destroy = %d, want 0", got)
		}
	})
}
