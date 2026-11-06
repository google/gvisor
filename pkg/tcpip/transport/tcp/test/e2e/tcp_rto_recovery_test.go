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

package tcp_rack_test

import (
	"bytes"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checker"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp/test/e2e"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp/testing/context"
)

// rtoRecoveryClock observes the reordering timer scheduled by packet handling.
// It neither injects a timer nor invokes a callback before its deadline.
type rtoRecoveryClock struct {
	*faketime.ManualClock
	watch chan struct{}
	armed chan time.Duration
	fired chan struct{}
}

func (c *rtoRecoveryClock) AfterFunc(d time.Duration, f func()) tcpip.Timer {
	if d > 0 && d <= 2*time.Millisecond {
		select {
		case <-c.watch:
			timer := c.ManualClock.AfterFunc(d, func() {
				f()
				close(c.fired)
			})
			c.armed <- d
			return timer
		default:
		}
	}
	return c.ManualClock.AfterFunc(d, f)
}

func TestRTORecoveryDrainsLostWindow(t *testing.T) {
	for _, mode := range []string{"rack", "sack", "rack_reordered", "rack_timer"} {
		t.Run(mode, func(t *testing.T) {
			const (
				advertisedMSS = 1460
				segments      = 16
				peerWindow    = 30000 // Also advertised by SendAckWithSACK.
			)
			clock := &rtoRecoveryClock{
				ManualClock: faketime.NewManualClock(),
				watch:       make(chan struct{}, 1),
				armed:       make(chan time.Duration, 1),
				fired:       make(chan struct{}),
			}
			processed := make(chan struct{}, 32)
			opts := context.Options{
				EnableV4: true,
				MTU:      header.IPv4MinimumSize + header.TCPMinimumSize + advertisedMSS,
				Clock:    clock,
				Probe: func(*tcp.TCPEndpointState) {
					processed <- struct{}{}
				},
			}
			if mode == "rack_timer" {
				opts.ClockResolution = time.Millisecond
			}
			c := context.NewWithOpts(t, opts)
			defer c.Cleanup()
			e2e.SetStackSACKPermitted(t, c, true)
			recovery := tcpip.TCPRecovery(tcpip.TCPRACKLossDetection)
			if mode == "sack" {
				recovery = 0
			}
			if err := c.Stack().SetTransportProtocolOption(tcp.ProtocolNumber, &recovery); err != nil {
				t.Fatalf("SetTransportProtocolOption(TCPRecovery): %s", err)
			}
			// Negotiate MSS and SACK, without timestamps or window scaling.
			c.CreateConnectedWithRawOptions(context.TestInitialSequenceNumber, peerWindow, -1,
				[]byte{2, 4, byte(advertisedMSS >> 8), byte(advertisedMSS & 0xff), 4, 2, 1, 1})
			if !c.EP.(*tcp.Endpoint).SACKPermitted {
				t.Fatal("SACK was not negotiated")
			}
			if c.EP.(*tcp.Endpoint).SendTSOk {
				t.Fatal("timestamps were unexpectedly negotiated")
			}
			info := func() tcpip.TCPInfoOption {
				t.Helper()
				var value tcpip.TCPInfoOption
				if err := c.EP.GetSockOpt(&value); err != nil {
					t.Fatalf("GetSockOpt(TCPInfoOption): %s", err)
				}
				return value
			}
			initial := info()
			mss := int(initial.SndMss)
			// maxOptionSize reserves two NOPs, the SACK option header, and
			// the maximum number of SACK blocks even when none are sent.
			const optionAllowance = 2 + 2 + 8*header.TCPMaxSACKBlocks
			if want := advertisedMSS - optionAllowance; mss != want {
				t.Fatalf("send payload = %d, want advertised MSS %d - option allowance %d = %d",
					mss, advertisedMSS, optionAllowance, want)
			}
			if initial.SndCwnd != tcp.InitialCwnd || tcp.InitialCwnd < 3 || tcp.InitialCwnd >= segments {
				t.Fatalf("initial congestion window = %d, want InitialCwnd (%d) in [3, %d)",
					initial.SndCwnd, tcp.InitialCwnd, segments)
			}
			if segments*mss > peerWindow {
				t.Fatalf("test data = %d bytes exceeds peer window %d", segments*mss, peerWindow)
			}
			data := make([]byte, segments*mss)
			for i := range data {
				data[i] = byte(i*17 + i/251)
			}
			clock.Advance(time.Millisecond)
			if n, err := c.EP.Write(bytes.NewReader(data), tcpip.WriteOptions{}); err != nil || n != int64(len(data)) {
				t.Fatalf("Write = (%d, %v), want (%d, nil)", n, err, len(data))
			}
			// Write has synchronized with the endpoint. Discard any handshake
			// probe notification before waiting for individual ACKs below.
			for len(processed) > 0 {
				<-processed
			}
			readSegment := func(offset int) {
				t.Helper()
				packet := c.GetPacketWithTimeout(time.Second)
				if packet == nil {
					t.Fatalf("no segment at offset %d: TCP=%+v, timeouts=%d",
						offset, info(), c.Stack().Stats().TCP.Timeouts.Value())
				}
				defer packet.Release()
				checker.IPv4(t, packet,
					checker.PayloadLen(header.TCPMinimumSize+mss),
					checker.TCP(
						checker.DstPort(context.TestPort),
						checker.TCPSeqNum(uint32(c.IRS.Add(1+seqnum.Size(offset)))),
						checker.TCPAckNum(context.TestInitialSequenceNumber+1),
						checker.TCPFlagsMatch(header.TCPFlagAck, ^header.TCPFlagPsh),
					),
				)
				h := header.TCP(header.IPv4(packet.AsSlice()).Payload())
				if !bytes.Equal(h.Payload(), data[offset:offset+mss]) {
					t.Fatalf("incorrect payload at offset %d", offset)
				}
			}
			ack := func(received int, sacks []header.SACKBlock) {
				t.Helper()
				c.SendAckWithSACK(context.TestInitialSequenceNumber+1, received, sacks)
				select {
				case <-processed:
				case <-time.After(time.Second):
					t.Fatal("ACK was not processed")
				}
			}
			checkRecovery := func() {
				t.Helper()
				if got := info().CcState; got != tcpip.RTORecovery {
					t.Fatalf("congestion state = %v, want RTORecovery", got)
				}
			}

			// Drop the whole initial flight and, with RACK, its tail probe.
			for i := 0; i < tcp.InitialCwnd; i++ {
				readSegment(i * mss)
			}
			if mode != "sack" {
				clock.Advance(time.Second)
				readSegment((tcp.InitialCwnd - 1) * mss)
				if got := c.Stack().Stats().TCP.Timeouts.Value(); got != 0 {
					t.Fatalf("timeouts before the tail probe = %d, want 0", got)
				}
			}
			clock.Advance(info().RTO)
			readSegment(0)
			if got := c.Stack().Stats().TCP.Timeouts.Value(); got != 1 {
				t.Fatalf("timeouts before recovery = %d, want 1", got)
			}
			checkRecovery()

			// Advance only milliseconds per ACK. A stalled sender cannot use
			// the next RTO to make the test pass.
			received := mss
			for {
				clock.Advance(time.Millisecond)
				ack(received, nil)
				if received < tcp.InitialCwnd*mss {
					checkRecovery()
				}
				if (mode == "rack_reordered" || mode == "rack_timer") && received == mss {
					// Hold the second retransmission while SACKing the third.
					readSegment(mss)
					readSegment(2 * mss)
					if mode == "rack_timer" {
						clock.Advance(10 * time.Millisecond)
						clock.watch <- struct{}{}
					}
					ack(received, []header.SACKBlock{{
						Start: c.IRS.Add(1 + seqnum.Size(2*mss)),
						End:   c.IRS.Add(1 + seqnum.Size(3*mss)),
					}})
					checkRecovery()
					if mode == "rack_timer" {
						var delay time.Duration
						select {
						case delay = <-clock.armed:
						case <-time.After(time.Second):
							t.Fatal("SACK did not arm the reordering timer")
						}
						clock.Advance(delay)
						select {
						case <-clock.fired:
						default:
							t.Fatal("reordering timer did not fire")
						}
						checkRecovery()
					}
					received = 3 * mss
					continue
				}
				if received == len(data) {
					break
				}
				readSegment(received)
				received += mss
			}
			if got := c.Stack().Stats().TCP.Timeouts.Value(); got != 1 {
				t.Fatalf("timeouts after recovery = %d, want 1", got)
			}
			if got := info().CcState; got != tcpip.Open {
				t.Fatalf("congestion state after final ACK = %v, want Open", got)
			}
		})
	}
}
