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

package tcp_test

import (
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp/testing/context"
	"gvisor.dev/gvisor/pkg/waiter"
)

type mockMarkMatcher struct {
	mark uint32
}

func (m *mockMarkMatcher) Match(hook stack.Hook, pkt *stack.PacketBuffer, inNicName, outNicName string) (bool, bool) {
	return pkt.Mark == m.mark, false
}

func TestTCPMarkFilteringE2E(t *testing.T) {
	c := context.New(t, 1500)
	defer c.Cleanup()

	// Setup IPTables rule to drop packets with mark 0x1234.
	table := stack.Table{
		Rules: []stack.Rule{
			{
				Filter: stack.IPHeaderFilter{
					Protocol: header.TCPProtocolNumber,
				},
				Matchers: []stack.Matcher{
					&mockMarkMatcher{mark: 0x1234},
				},
				Target: &stack.DropTarget{},
			},
			{
				Target: &stack.AcceptTarget{},
			},
		},
		BuiltinChains: [stack.NumHooks]int{
			stack.Output: 0,
		},
		Underflows: [stack.NumHooks]int{
			stack.Output: 0,
		},
	}
	c.Stack().IPTables().ForceReplaceTable(stack.FilterID, table, false /* ipv4 */)

	c.Create(-1)

	// Set SO_MARK to 0x1234 and attempt to connect (which should fail).
	c.EP.SocketOptions().SetMark(0x1234)
	waitEntry, notifyCh := waiter.NewChannelEntry(waiter.WritableEvents)
	c.WQ.EventRegister(&waitEntry)
	defer c.WQ.EventUnregister(&waitEntry)
	err := c.EP.Connect(tcpip.FullAddress{Addr: context.TestAddr, Port: context.TestPort})
	if _, ok := err.(*tcpip.ErrConnectStarted); !ok {
		t.Fatalf("Unexpected return value from Connect: %v", err)
	}

	// Verify that SYN is dropped (we get a timeout trying to read it from link layer).
	// We use a short timeout because we expect it to be dropped.
	p := c.GetPacketWithTimeout(500 * time.Millisecond)
	if p != nil {
		p.Release()
		t.Fatalf("Expected SYN packet to be dropped by IPTables rule, but it was received")
	}

	c.EP.Close()
	<-notifyCh
	c.EP = nil

	// Now verify that a socket with a different mark can connect.
	c.Create(-1)
	c.EP.SocketOptions().SetMark(0x5678)
	err = c.EP.Connect(tcpip.FullAddress{Addr: context.TestAddr, Port: context.TestPort})
	if _, ok := err.(*tcpip.ErrConnectStarted); !ok {
		t.Fatalf("Unexpected return value from Connect: %v", err)
	}
	b := c.GetPacket()
	if b == nil {
		t.Fatalf("Expected to receive SYN packet for mark 0x5678, but got none")
	}
	defer b.Release()
	tcpHdr := header.TCP(header.IPv4(b.AsSlice()).Payload())
	if tcpHdr.Flags() != header.TCPFlagSyn {
		t.Fatalf("Expected SYN packet, got flags: %v", tcpHdr.Flags())
	}
}
