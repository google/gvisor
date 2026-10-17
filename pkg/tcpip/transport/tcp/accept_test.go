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
	"context"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/waiter"
)

func TestListenerShrinkingBacklogUsesCookies(t *testing.T) {
	// Bound waits with real time, but do not advance the stack's clock. This
	// keeps SYN-ACK retransmissions and handshake expiry out of this test.
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	link := channel.New(16, 1500, "")
	s := stack.New(stack.Options{
		Clock:              faketime.NewManualClock(),
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{NewProtocol},
	})
	t.Cleanup(func() {
		s.Destroy()
		link.Close()
	})

	// Exercise backlog-based cookie selection, not unconditional cookies.
	alwaysUseSynCookies := tcpip.TCPAlwaysUseSynCookies(false)
	if err := s.SetTransportProtocolOption(ProtocolNumber, &alwaysUseSynCookies); err != nil {
		t.Fatalf("SetTransportProtocolOption(TCPAlwaysUseSynCookies=false): %v", err)
	}

	const (
		nicID       tcpip.NICID = 1
		listenPort  uint16      = 8080
		cookiePort  uint16      = 40002
		cookieSeq   uint32      = 200
		initialSize             = 4
		reducedSize             = 2
	)
	local := tcpip.AddrFrom4([4]byte{192, 0, 2, 1})
	remote := tcpip.AddrFrom4([4]byte{192, 0, 2, 2})

	if err := s.CreateNIC(nicID, link); err != nil {
		t.Fatalf("CreateNIC: %v", err)
	}
	if err := s.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   local,
			PrefixLen: 24,
		},
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress: %v", err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: nicID}})

	var wq waiter.Queue
	endpoint, err := s.NewEndpoint(ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	listener := endpoint.(*Endpoint)
	t.Cleanup(listener.Close)

	if err := listener.Bind(tcpip.FullAddress{Port: listenPort}); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	// Endpoint.Listen takes the accept queue capacity directly. The SYN
	// backlog is one less; the syscall layer's backlog adjustment is not used.
	if err := listener.Listen(initialSize); err != nil {
		t.Fatalf("Listen(%d): %v", initialSize, err)
	}

	entry, ready := waiter.NewChannelEntry(waiter.ReadableEvents)
	wq.EventRegister(&entry)
	defer wq.EventUnregister(&entry)

	send := func(port uint16, flags header.TCPFlags, seq, ack uint32) {
		t.Helper()
		b := make([]byte, header.IPv4MinimumSize+header.TCPMinimumSize)
		ip := header.IPv4(b)
		ip.Encode(&header.IPv4Fields{
			TotalLength: uint16(len(b)),
			TTL:         64,
			Protocol:    uint8(ProtocolNumber),
			SrcAddr:     remote,
			DstAddr:     local,
		})
		ip.SetChecksum(^ip.CalculateChecksum())

		tcp := header.TCP(b[header.IPv4MinimumSize:])
		tcp.Encode(&header.TCPFields{
			SrcPort:    port,
			DstPort:    listenPort,
			SeqNum:     seq,
			AckNum:     ack,
			DataOffset: header.TCPMinimumSize,
			Flags:      flags,
			WindowSize: 65535,
		})
		pseudo := header.PseudoHeaderChecksum(ProtocolNumber, remote, local, header.TCPMinimumSize)
		tcp.SetChecksum(^tcp.CalculateChecksum(pseudo))

		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(b),
		})
		defer pkt.DecRef()
		link.InjectInbound(ipv4.ProtocolNumber, pkt)
	}

	readSYNACK := func(port uint16, ack uint32) uint32 {
		t.Helper()
		pkt := link.ReadContext(ctx)
		if pkt == nil {
			t.Fatalf("no SYN-ACK for port %d: %v", port, ctx.Err())
		}
		defer pkt.DecRef()

		b := pkt.TransportHeader().Slice()
		if len(b) < header.TCPMinimumSize {
			t.Fatalf("TCP header length = %d, want at least %d", len(b), header.TCPMinimumSize)
		}
		h := header.TCP(b)
		if h.SourcePort() != listenPort ||
			h.DestinationPort() != port ||
			h.Flags() != header.TCPFlagSyn|header.TCPFlagAck ||
			h.AckNumber() != ack {
			t.Fatalf("packet src=%d dst=%d flags=%v ACK=%d, want src=%d dst=%d SYN-ACK ACK=%d",
				h.SourcePort(), h.DestinationPort(), h.Flags(), h.AckNumber(),
				listenPort, port, ack)
		}
		return h.SequenceNumber()
	}

	type listenerState struct {
		capacity        int
		pending         int
		accepted        int
		cookiesSent     uint64
		cookiesReceived uint64
	}
	snapshot := func() listenerState {
		// A SYN-ACK becomes observable before handleListenSegment finishes
		// updating pendingEndpoints or its cookie statistics. After reading
		// that packet, take mu to wait for the handling critical section.
		listener.mu.Lock()
		defer listener.mu.Unlock()
		listener.acceptMu.Lock()
		defer listener.acceptMu.Unlock()
		return listenerState{
			capacity:        listener.acceptQueue.capacity,
			pending:         len(listener.acceptQueue.pendingEndpoints),
			accepted:        listener.acceptQueue.endpoints.Len(),
			cookiesSent:     s.Stats().TCP.ListenOverflowSynCookieSent.Value(),
			cookiesReceived: s.Stats().TCP.ListenOverflowSynCookieRcvd.Value(),
		}
	}
	checkState := func(stage string, want listenerState) {
		t.Helper()
		if got := snapshot(); got != want {
			t.Fatalf("%s: listener state = %+v, want %+v", stage, got, want)
		}
	}

	checkState("initial listener", listenerState{capacity: initialSize})

	// Leave two distinct connections in SYN-RCVD without sending their ACKs.
	for _, port := range []uint16{40000, 40001} {
		send(port, header.TCPFlagSyn, 100, 0)
		_ = readSYNACK(port, 101)
	}
	checkState("before shrinking", listenerState{
		capacity: initialSize,
		pending:  2,
	})

	if err := listener.Listen(reducedSize); err != nil {
		t.Fatalf("Listen(%d): %v", reducedSize, err)
	}
	checkState("after shrinking", listenerState{
		capacity: reducedSize,
		pending:  2,
	})

	// The two existing handshakes exceed the reduced SYN backlog of one.
	// A new SYN must use a cookie instead of allocating a third pending slot.
	send(cookiePort, header.TCPFlagSyn, cookieSeq, 0)
	cookie := readSYNACK(cookiePort, cookieSeq+1)
	checkState("after cookie SYN-ACK", listenerState{
		capacity:    reducedSize,
		pending:     2,
		cookiesSent: 1,
	})

	// A valid cookie ACK must still establish a connection even though the
	// pending SYN queue exceeds its new limit; the accept queue is empty.
	send(cookiePort, header.TCPFlagAck, cookieSeq+1, cookie+1)
	for {
		var peer tcpip.FullAddress
		accepted, _, err := listener.Accept(&peer)
		if err == nil {
			t.Cleanup(accepted.Close)
			if peer.Addr != remote || peer.Port != cookiePort {
				t.Fatalf("accepted peer = %+v, want address %v and port %d", peer, remote, cookiePort)
			}
			if got, want := accepted.State(), uint32(StateEstablished); got != want {
				t.Fatalf("accepted endpoint state = %d, want %d", got, want)
			}
			checkState("after accepting cookie connection", listenerState{
				capacity:        reducedSize,
				pending:         2,
				cookiesSent:     1,
				cookiesReceived: 1,
			})
			return
		}
		if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
			t.Fatalf("Accept: %v", err)
		}
		select {
		case <-ready:
		case <-ctx.Done():
			t.Fatalf("cookie ACK did not establish a connection: %v", ctx.Err())
		}
	}
}
