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

package tcp_delayed_ack_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/state"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checker"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp/test/e2e"
	testcontext "gvisor.dev/gvisor/pkg/tcpip/transport/tcp/testing/context"
)

func TestPendingDelayedACKAcrossRestore(t *testing.T) {
	c, _ := newInteractive(t)
	defer c.Cleanup()
	c.Stack().SetAllowLiveTCPMigration(true)
	c.Stack().SetRemoveConf(true)

	sendData(c, payloadSize, responseSize)
	c.CheckNoPacketTimeout("ACK arrived before checkpoint", noPacketWait)
	if n, err := c.EP.GetSockOptInt(tcpip.ReceiveQueueSizeOption); err != nil || n != payloadSize {
		t.Fatalf("receive queue before checkpoint: got (%d, %v), want (%d, nil)", n, err, payloadSize)
	}
	var image bytes.Buffer
	if _, err := state.Save(context.Background(), &image, c.Stack()); err != nil {
		t.Fatalf("save: %v", err)
	}
	c.Stack().Resume()

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	defer s.Destroy()
	s.SetAllowLiveTCPMigration(true)
	if _, err := state.Load(context.Background(), &image, s); err != nil {
		t.Fatalf("load: %v", err)
	}
	link := channel.New(1000, e2e.DefaultMTU, "")
	defer link.Close()
	if err := s.CreateNIC(1, link); err != nil {
		t.Fatalf("CreateNIC: %s", err)
	}
	if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: testcontext.StackAddrWithPrefix,
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress: %s", err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	s.Restore()
	tcpip.AsyncLoading.Wait()

	wantACK := uint32(testcontext.TestInitialSequenceNumber) + 1 + 2*payloadSize
	readACK := func(ack uint32) bool {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		pkt := link.ReadContext(ctx)
		if pkt == nil {
			return false
		}
		defer pkt.DecRef()
		v := pkt.ToView()
		defer v.Release()
		checker.IPv4(t, v, checker.PayloadLen(header.TCPMinimumSize), checker.TCP(
			checker.DstPort(testcontext.TestPort),
			checker.TCPSeqNum(uint32(c.IRS)+1+responseSize),
			checker.TCPAckNum(ack),
			checker.TCPFlags(header.TCPFlagAck),
		))
		return true
	}
	s.Clock().(*faketime.ManualClock).Advance(delayedACKTimeout)
	ackByDeadline := readACK(wantACK)

	// Send fresh bytes and require the cumulative ACK to advance. This checks
	// that the restored route and connection work even if the timer never fired.
	const extra = 2 * payloadSize
	headers := testcontext.Headers{
		SrcPort: testcontext.TestPort,
		DstPort: c.Port,
		Flags:   header.TCPFlagAck,
		SeqNum:  testcontext.TestInitialSequenceNumber + 1 + 2*payloadSize,
		AckNum:  c.IRS.Add(1 + responseSize),
		RcvWnd:  30000,
	}
	next := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: c.BuildSegment(make([]byte, extra), &headers),
	})
	link.InjectInbound(ipv4.ProtocolNumber, next)
	next.DecRef()
	if !readACK(wantACK + extra) {
		t.Fatal("restored connection did not ACK the new bytes")
	}
	if t.Failed() {
		return
	}
	t.Logf("restored: ACK %d by %v = %t, ACK %d after new data", wantACK, delayedACKTimeout, ackByDeadline, wantACK+extra)
	if !ackByDeadline {
		t.Error("restored TCP receiver lost its pending ACK")
	}
}
