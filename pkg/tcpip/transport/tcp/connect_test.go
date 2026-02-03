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

package tcp

import (
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// TestResetConnectionLockedNilSndRcv verifies that resetConnectionLocked does
// not panic when e.snd and e.rcv are nil, which occurs for endpoints in
// handshake states (e.g. SynSent) that have not yet initialized their sender
// and receiver. In this case, per Linux behavior, the RST is sent with a
// sequence number of zero and a receive window of zero.
func TestResetConnectionLockedNilSndRcv(t *testing.T) {
	fClock := faketime.NewManualClock()
	s := stack.New(stack.Options{
		TransportProtocols: []stack.TransportProtocolFactory{NewProtocol},
		Clock:              fClock,
	})

	ep := &Endpoint{
		stack: s,
		snd:   nil,
		rcv:   nil,
	}
	ep.setEndpointState(StateSynSent)

	ep.mu.Lock()
	ep.resetConnectionLocked(&tcpip.ErrConnectionAborted{})
	ep.mu.Unlock()

	if got, want := ep.EndpointState(), StateError; got != want {
		t.Errorf("endpoint state after resetConnectionLocked = %v, want %v", got, want)
	}
}
