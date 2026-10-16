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

// Package tcp_acktiming_test verifies that TCP RTT measurements are anchored to
// the time an ACK arrived at the stack (its ingress timestamp, segment.rcvdTime)
// rather than the time the stack got around to processing it.
//
// These are regression tests for the gvisor#9707 / gvisor#9778 family: when the
// sending endpoint is busy (e.g. the application holds the endpoint lock during
// a Write that synchronously flushes a window of segments, paying real
// per-packet cost such as WireGuard encryption), inbound ACKs sit unprocessed in
// the endpoint's segment queue. If an RTT is measured against the processing-time
// clock instead of the ACK's ingress time, it is inflated by that internal
// delay. For RACK this corrupts RACK.RTT/minRTT and the reorder window and
// triggers spurious loss detection; for the main-path RTT it inflates SRTT/RTO.
package tcp_acktiming_test

import (
	"bytes"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp/test/e2e"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp/testing/context"
)

const (
	maxPayload = 10
	mtu        = header.TCPMinimumSize + header.IPv4MinimumSize + 40 + maxPayload
)

func TestMain(m *testing.M) {
	refs.SetLeakMode(refs.NoLeakChecking)
	m.Run()
}

// agedACKResult holds the sender state captured by the probe when the aged ACK
// was processed.
type agedACKResult struct {
	rackRTT time.Duration
	srtt    time.Duration
	rto     time.Duration
}

type tcpStateSample struct {
	srtt    time.Duration
	rackRTT time.Duration
	rto     time.Duration
}

// runAgedACK establishes a connection, sends one segment, and then processes its
// ACK after an internal processing delay of processHold (created by holding the
// endpoint lock via StopWork while virtual time advances). The ACK genuinely
// arrives trueRTT after transmission. useTS selects whether the connection
// negotiates TCP timestamps (which selects the timestamp vs non-timestamp RTT
// path in the sender). It returns the sender RTT state observed when the aged
// ACK is processed.
func runAgedACK(t *testing.T, useTS bool, trueRTT, processHold time.Duration) agedACKResult {
	t.Helper()

	clock := faketime.NewManualClock()

	stateCh := make(chan tcpStateSample, 256)
	probe := func(state *tcp.TCPEndpointState) {
		// Non-blocking: never stall the stack's processing goroutine.
		select {
		case stateCh <- tcpStateSample{
			srtt:    state.Sender.RTTState.SRTT,
			rackRTT: state.Sender.RACKState.RTT,
			rto:     state.Sender.RTO,
		}:
		default:
		}
	}

	c := context.NewWithOpts(t, context.Options{
		EnableV4: true,
		EnableV6: true,
		MTU:      mtu,
		Clock:    clock,
		Probe:    probe,
	})
	defer c.Cleanup()

	e2e.SetStackSACKPermitted(t, c, true)
	// Always negotiate timestamps so we can choose, per test, whether the
	// injected ACK carries a TSEcr (which selects the timestamp RTT path,
	// snd.go) or not (the non-timestamp path). rep is the peer (link) side.
	rep := e2e.CreateConnectedWithSACKAndTS(c)

	tcpEP, ok := c.EP.(interface {
		StopWork()
		ResumeWork()
	})
	if !ok {
		t.Fatalf("endpoint %T does not expose StopWork/ResumeWork", c.EP)
	}

	data := make([]byte, maxPayload)
	for i := range data {
		data[i] = byte(i)
	}

	// Send one segment and read it off the link, capturing the data segment's
	// TSVal so the ACK below can echo it back as TSEcr (selecting the timestamp
	// RTT path).
	var r bytes.Reader
	r.Reset(data)
	if _, err := c.EP.Write(&r, tcpip.WriteOptions{}); err != nil {
		t.Fatalf("Write failed: %s", err)
	}
	dataPkt := c.GetPacket()
	dataTCP := header.TCP(header.IPv4(dataPkt.AsSlice()).Payload())
	dataTSVal := dataTCP.ParsedOptions().TSVal
	dataPkt.Release()
	if useTS && dataTSVal == 0 {
		t.Fatal("data segment carried no TSVal; cannot exercise the timestamp RTT path")
	}

	// The ACK genuinely arrives one RTT after transmission.
	clock.Advance(trueRTT)

	// Drain probe samples produced so far so we observe the post-ACK state.
	for len(stateCh) > 0 {
		<-stateCh
	}

	// Create the internal processing delay: hold the endpoint lock so the
	// injected ACK cannot be processed, advance virtual time while it sits in
	// the segment queue, then release the lock so it is processed against the
	// advanced clock. With the fix, the RTT is computed from the ACK's ingress
	// time (rcvdTime) and is not inflated.
	//
	// NB: StopWork takes the endpoint lock directly; it models the processing
	// delay (segment stamped at SendAck time, processed after the clock
	// advanced), not the exact LockUser/UnlockUser handoff of the real bug.
	rep.NextSeqNum = seqnum.Value(context.TestInitialSequenceNumber).Add(1)
	rep.AckNum = c.IRS.Add(1 + seqnum.Size(len(data)))
	rep.Flags = header.TCPFlagAck
	tcpEP.StopWork()
	if useTS {
		// Echo the data segment's TSVal as TSEcr so the sender takes the
		// timestamp RTT path (s.ep.elapsed(rcvdSeg.rcvdTime, TSEcr)).
		rep.RecentTS = dataTSVal
		rep.SendPacketWithTS(nil, rep.TSVal+1)
	} else {
		c.SendAck(seqnum.Value(context.TestInitialSequenceNumber).Add(1), len(data))
	}
	// Keep processHold below the (3s test) RTO so no retransmit timer fires
	// while we hold the lock.
	clock.Advance(processHold)
	tcpEP.ResumeWork()

	// Wait for the probe to report the state after the aged ACK is processed.
	deadline := time.After(5 * time.Second)
	for {
		select {
		case st := <-stateCh:
			// The ACK acknowledges our one segment, advancing SndUna. Once that
			// has happened the RTT state reflects this ACK.
			if st.srtt != 0 {
				return agedACKResult{
					rackRTT: st.rackRTT,
					srtt:    st.srtt,
					rto:     st.rto,
				}
			}
		case <-deadline:
			t.Fatal("timed out waiting for the aged ACK to be processed")
		}
	}
}

// TestRACKRTTNotInflatedByProcessingDelay covers rackControl.update (RACK RTT).
func TestRACKRTTNotInflatedByProcessingDelay(t *testing.T) {
	const (
		trueRTT     = 50 * time.Millisecond
		processHold = 250 * time.Millisecond
	)
	got := runAgedACK(t, true /* useTS */, trueRTT, processHold)
	t.Logf("true RTT=%v hold=%v: RACK RTT=%v SRTT=%v", trueRTT, processHold, got.rackRTT, got.srtt)
	if got.rackRTT > trueRTT+processHold/2 {
		t.Errorf("RACK RTT inflated by internal processing delay: got %v, want <= %v; "+
			"RTT measured against processing time instead of the ACK's ingress time (rcvdTime)",
			got.rackRTT, trueRTT+processHold/2)
	}
}

// TestSRTTNotInflatedByProcessingDelayTS covers the timestamp-based main-path
// RTT in sender.handleRcvdSegment.
func TestSRTTNotInflatedByProcessingDelayTS(t *testing.T) {
	const (
		trueRTT     = 50 * time.Millisecond
		processHold = 250 * time.Millisecond
	)
	got := runAgedACK(t, true /* useTS */, trueRTT, processHold)
	t.Logf("true RTT=%v hold=%v: SRTT=%v RTO=%v", trueRTT, processHold, got.srtt, got.rto)
	// SRTT is the first sample here (smoothed estimator seeded by this RTT), so
	// an inflated sample shows up close to trueRTT+processHold.
	if got.srtt > trueRTT+processHold/2 {
		t.Errorf("SRTT inflated by internal processing delay (TS path): got %v, want <= %v",
			got.srtt, trueRTT+processHold/2)
	}
}

// TestSRTTNotInflatedByProcessingDelayNoTS covers the non-timestamp main-path
// RTT in sender.handleRcvdSegment.
func TestSRTTNotInflatedByProcessingDelayNoTS(t *testing.T) {
	const (
		trueRTT     = 50 * time.Millisecond
		processHold = 250 * time.Millisecond
	)
	got := runAgedACK(t, false /* useTS */, trueRTT, processHold)
	t.Logf("true RTT=%v hold=%v: SRTT=%v RTO=%v", trueRTT, processHold, got.srtt, got.rto)
	if got.srtt > trueRTT+processHold/2 {
		t.Errorf("SRTT inflated by internal processing delay (non-TS path): got %v, want <= %v",
			got.srtt, trueRTT+processHold/2)
	}
}

// TestSRTTAfterTailLossProbe checks Karn's rule at the packet boundary: an ACK
// after retransmission supplies an RTT sample only when its timestamp identifies
// the transmission. A subsequent ACK of new data must still supply a sample.
func TestSRTTAfterTailLossProbe(t *testing.T) {
	// Starting at 10ms, the PTO is 220ms and the ACK arrives 50ms later.
	// Echoing the original or retransmission samples 270ms or 50ms, giving
	// SRTT=(7*10+sample)/8: 42.5ms or 15ms (RFC 6298, section 2.3).
	// Without timestamps, SRTT stays 10ms. The next 40ms sample gives
	// 42.1875ms, 18.125ms, or 13.75ms, respectively.
	for _, test := range []struct {
		name         string
		timestamps   bool
		echoOriginal bool
		wantSRTT     time.Duration
		wantNextSRTT time.Duration
		wantReoWnd   time.Duration
	}{
		{name: "no_timestamp", wantSRTT: 10 * time.Millisecond, wantNextSRTT: 13750 * time.Microsecond, wantReoWnd: 2500 * time.Microsecond},
		{name: "original_timestamp", timestamps: true, echoOriginal: true, wantSRTT: 42500 * time.Microsecond, wantNextSRTT: 42187500 * time.Nanosecond, wantReoWnd: 42500 * time.Microsecond},
		{name: "retransmit_timestamp", timestamps: true, wantSRTT: 15 * time.Millisecond, wantNextSRTT: 18125 * time.Microsecond, wantReoWnd: 12500 * time.Microsecond},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := newRTTTestContext(t, test.timestamps, 0)
			clock, c := h.clock, h.c
			send := func() uint32 { return h.send(h.mss) }
			ack := func(echo uint32) tcp.TCPSenderState { return h.ack(h.sent, echo) }

			stamp := send()
			clock.Advance(10 * time.Millisecond)
			before := ack(stamp)
			if got, want := before.RTTState.SRTT, 10*time.Millisecond; got != want {
				t.Fatalf("initial SRTT = %v, want %v", got, want)
			}
			// Let the minimum's window expire with no outstanding data.
			// The ambiguous ACK below must not replace it. Timestamp-based
			// measurements may do so; the reorder window is capped by SRTT.
			clock.Advance(6 * time.Minute)
			original := send()
			// One outstanding packet adds the 200ms delayed-ACK allowance
			// to twice SRTT. This PTO precedes the test's three-second RTO.
			pto := 2*before.RTTState.SRTT + 200*time.Millisecond
			if pto >= before.RTO {
				t.Fatalf("PTO %v is not before RTO %v", pto, before.RTO)
			}
			clock.Advance(pto)
			retransmit := h.readPacket(h.sent-h.mss, h.mss)
			if got, want := c.Stack().Stats().TCP.Retransmits.Value(), uint64(1); got != want {
				t.Fatalf("retransmissions = %d, want %d", got, want)
			}
			if test.timestamps {
				if got, want := retransmit-original, uint32(pto/time.Millisecond); got != want {
					t.Fatalf("retransmission timestamp advance = %d, want %d", got, want)
				}
			}
			stamp = retransmit
			if test.echoOriginal {
				stamp = original
			}
			clock.Advance(50 * time.Millisecond)
			after := ack(stamp)
			if got, want := after.RTTState.SRTT, test.wantSRTT; got != want {
				t.Fatalf("SRTT after PTO ACK = %v, want %v", got, want)
			}
			if got, want := after.RACKState.ReoWnd, test.wantReoWnd; got != want {
				t.Fatalf("reorder window after PTO ACK = %v, want %v", got, want)
			}
			if !test.timestamps {
				if got, want := after.RTTState, before.RTTState; got != want {
					t.Errorf("RTT state after ambiguous ACK = %+v, want %+v", got, want)
				}
				if got, want := after.RTO, before.RTO; got != want {
					t.Errorf("RTO after ambiguous ACK = %v, want %v", got, want)
				}
			}
			stamp = send()
			clock.Advance(40 * time.Millisecond)
			next := ack(stamp)
			if got, want := next.RTTState.SRTT, test.wantNextSRTT; got != want {
				t.Fatalf("SRTT after new-data ACK = %v, want %v", got, want)
			}
		})
	}
}

// rttTestContext drives real ACK accounting with virtual time. Probe snapshots
// are copied into a bounded channel and read only after the TCP worker drains.
type rttTestContext struct {
	t          *testing.T
	c          *context.Context
	clock      *faketime.ManualClock
	peer       *context.RawEndpoint
	states     chan tcp.TCPSenderState
	timestamps bool
	mss        int
	sent       int
}

func newRTTTestContext(t *testing.T, timestamps bool, handshakeRTT time.Duration) *rttTestContext {
	t.Helper()
	h := &rttTestContext{t: t, clock: faketime.NewManualClock(), timestamps: timestamps, states: make(chan tcp.TCPSenderState, 32)}
	h.clock.Advance(time.Second)
	h.c = context.NewWithOpts(t, context.Options{
		EnableV4: true,
		MTU:      mtu,
		Clock:    h.clock,
		Probe: func(state *tcp.TCPEndpointState) {
			select {
			case h.states <- state.Sender:
			default:
			}
		},
	})
	t.Cleanup(h.c.Cleanup)
	e2e.SetStackSACKPermitted(t, h.c, true)
	e2e.SetStackTCPRecovery(t, h.c, int(tcpip.TCPRACKLossDetection))
	if handshakeRTT != 0 {
		if timestamps {
			t.Fatal("manual handshake does not negotiate timestamps")
		}
		h.c.Create(-1)
		if err := h.c.EP.Connect(tcpip.FullAddress{Addr: context.TestAddr, Port: context.TestPort}); err == nil {
			t.Fatal("Connect unexpectedly completed before SYN-ACK")
		} else if _, ok := err.(*tcpip.ErrConnectStarted); !ok {
			t.Fatalf("Connect: %s", err)
		}
		pkt := h.c.GetPacket()
		syn := header.TCP(header.IPv4(pkt.AsSlice()).Payload())
		if got, want := syn.Flags(), header.TCPFlagSyn; got != want {
			t.Fatalf("handshake flags = %v, want %v", got, want)
		}
		h.c.IRS = seqnum.Value(syn.SequenceNumber())
		h.c.Port = syn.SourcePort()
		pkt.Release()
		h.clock.Advance(handshakeRTT)
		h.c.SendPacket(nil, &context.Headers{
			SrcPort: context.TestPort, DstPort: h.c.Port,
			Flags:  header.TCPFlagSyn | header.TCPFlagAck,
			SeqNum: context.TestInitialSequenceNumber, AckNum: h.c.IRS.Add(1), RcvWnd: 30000,
			TCPOpts: []byte{header.TCPOptionSACKPermitted, 2, header.TCPOptionNOP, header.TCPOptionNOP},
		})
		pkt = h.c.GetPacket()
		if got, want := header.TCP(header.IPv4(pkt.AsSlice()).Payload()).Flags(), header.TCPFlagAck; got != want {
			t.Fatalf("final handshake flags = %v, want %v", got, want)
		}
		pkt.Release()
		h.c.Stack().Pause()
		h.c.Stack().Resume()
	} else if timestamps {
		h.peer = e2e.CreateConnectedWithSACKAndTS(h.c)
	} else {
		h.peer = e2e.CreateConnectedWithSACKPermittedOption(h.c)
	}
	var info tcpip.TCPInfoOption
	if err := h.c.EP.GetSockOpt(&info); err != nil {
		t.Fatalf("GetSockOpt(TCPInfoOption): %s", err)
	}
	h.mss = int(info.SndMss)
	if h.mss <= 1 {
		t.Fatalf("send MSS = %d, need distinct full-sized and runt packets", h.mss)
	}
	return h
}

func (h *rttTestContext) readPacket(offset, size int) uint32 {
	h.t.Helper()
	pkt := h.c.GetPacket()
	defer pkt.Release()
	tcp := header.TCP(header.IPv4(pkt.AsSlice()).Payload())
	if got, want := seqnum.Value(tcp.SequenceNumber()), h.c.IRS.Add(1+seqnum.Size(offset)); got != want {
		h.t.Fatalf("packet sequence = %v, want %v", got, want)
	}
	if got, want := tcp.Payload(), bytes.Repeat([]byte{0xab}, size); !bytes.Equal(got, want) {
		h.t.Fatalf("packet payload = %x, want %x", got, want)
	}
	if got, want := tcp.ParsedOptions().TS, h.timestamps; got != want {
		h.t.Fatalf("packet timestamp option = %t, want %t", got, want)
	}
	return tcp.ParsedOptions().TSVal
}

func (h *rttTestContext) send(size int) uint32 {
	h.t.Helper()
	data := bytes.Repeat([]byte{0xab}, size)
	if n, err := h.c.EP.Write(bytes.NewReader(data), tcpip.WriteOptions{}); err != nil || n != int64(size) {
		h.t.Fatalf("Write = (%d, %v), want (%d, nil)", n, err, size)
	}
	ts := h.readPacket(h.sent, size)
	h.sent += size
	return ts
}

func (h *rttTestContext) ack(received int, echo uint32, sacks ...header.SACKBlock) tcp.TCPSenderState {
	h.t.Helper()
	ack := h.c.IRS.Add(1 + seqnum.Size(received))
	if h.timestamps {
		if len(sacks) != 0 {
			h.t.Fatal("timestamp ACK helper does not encode SACK blocks")
		}
		h.peer.AckNum = ack
		h.peer.Flags = header.TCPFlagAck
		h.peer.RecentTS = echo
		h.peer.SendPacketWithTS(nil, h.peer.TSVal+1)
	} else {
		h.c.SendAckWithSACK(seqnum.Value(context.TestInitialSequenceNumber).Add(1), received, sacks)
	}
	// Pause drains the queued ACK while virtual time stays fixed. This is the
	// same synchronization used by the existing CUBIC packet fixtures.
	h.c.Stack().Pause()
	h.c.Stack().Resume()
	var last tcp.TCPSenderState
	found := false
	for len(h.states) != 0 {
		last = <-h.states
		found = true
	}
	if !found || last.SndUna != ack {
		h.t.Fatalf("ACK state: found=%t SndUna=%v, want %v", found, last.SndUna, ack)
	}
	return last
}

func (h *rttTestContext) exchange(size int, rtt time.Duration) tcp.TCPSenderState {
	h.t.Helper()
	ts := h.send(size)
	h.clock.Advance(rtt)
	st := h.ack(h.sent, ts)
	if got, want := st.RACKState.RTT, rtt; got != want {
		h.t.Fatalf("RACK RTT = %v, want %v", got, want)
	}
	return st
}

// These histories end with high samples unless a low-path return is explicit.
// A lone runt models receiver delay; its geometry is a conservative heuristic,
// not evidence of the peer's actual delayed-ACK policy.
func TestMinimumRTTACKHistory(t *testing.T) {
	for _, test := range []struct {
		name    string
		runt    bool
		samples []int
		wantMin []int
		idle    time.Duration
	}{
		{name: "sustained_path", samples: []int{100, 100, 100, 100, 100, 100}, wantMin: []int{10, 10, 10, 10, 100, 100}, idle: time.Minute},
		{name: "lone_runt_delay", runt: true, samples: []int{100, 100, 100, 100, 100, 100}, wantMin: []int{10, 10, 10, 10, 10, 10}, idle: time.Minute},
		{name: "unchanged_path", samples: []int{10, 10, 10, 10, 10, 10}, wantMin: []int{10, 10, 10, 10, 10, 10}, idle: time.Minute},
		{name: "spike_then_low", samples: []int{100, 10, 10, 10, 10, 10}, wantMin: []int{10, 10, 10, 10, 10, 10}, idle: time.Minute},
		{name: "low_path_return", samples: []int{100, 100, 100, 100, 100, 100, 5}, wantMin: []int{10, 10, 10, 10, 100, 100, 5}, idle: time.Minute},
		{name: "idle_then_high", samples: []int{100}, wantMin: []int{100}, idle: 6 * time.Minute},
		{name: "idle_then_runt_delay", runt: true, samples: []int{100}, wantMin: []int{10}, idle: 6 * time.Minute},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := newRTTTestContext(t, false, 0)
			h.exchange(h.mss, 10*time.Millisecond)
			size := h.mss
			if test.runt {
				size = 1
			}
			for i, rttMillis := range test.samples {
				// Idle only after the previous flight is completely ACKed.
				h.clock.Advance(test.idle)
				st := h.exchange(size, time.Duration(rttMillis)*time.Millisecond)
				want := min(time.Duration(test.wantMin[i])*time.Millisecond/4, st.RTTState.SRTT)
				if got := st.RACKState.ReoWnd; got != want {
					t.Fatalf("sample %d: reorder window = %v, want %v (SRTT %v)", i, got, want, st.RTTState.SRTT)
				}
			}
			if got, want := h.c.Stack().Stats().TCP.Retransmits.Value(), uint64(0); got != want {
				t.Fatalf("history retransmissions = %d, want %d", got, want)
			}
			if test.name != "sustained_path" {
				return
			}

			// Actual reordered delivery on the longer path: the newer
			// segment is SACKed at 101ms, then the older original arrives
			// at 110ms. The old lifetime minimum retransmitted it at ~104ms.
			start := h.sent
			h.send(h.mss)
			h.clock.Advance(time.Millisecond)
			h.send(h.mss)
			h.clock.Advance(100 * time.Millisecond)
			st := h.ack(start, 0, header.SACKBlock{Start: h.c.IRS.Add(1 + seqnum.Size(start+h.mss)), End: h.c.IRS.Add(1 + seqnum.Size(h.sent))})
			if got, want := st.SackedOut, 1; got != want {
				t.Fatalf("SACKed packets = %d, want %d", got, want)
			}
			h.clock.Advance(9 * time.Millisecond)
			st = h.ack(h.sent, 0)
			if got, want := h.c.Stack().Stats().TCP.Retransmits.Value(), uint64(0); got != want {
				t.Fatalf("retransmissions before original delivery = %d, want %d", got, want)
			}
			if got, want := st.Outstanding, 0; got != want {
				t.Fatalf("outstanding after original delivery = %d, want %d", got, want)
			}
			if st.FastRecovery.Active {
				t.Fatal("entered recovery before the original packet arrived")
			}
		})
	}
}

func TestMinimumRTTPartialACK(t *testing.T) {
	// Two outstanding packets schedule PTO at twice the initial 10ms SRTT.
	// Deliver the first ACK before that probe makes its timing ambiguous.
	const sampleRTT = 15 * time.Millisecond
	for _, crossing := range []bool{false, true} {
		name := "one_original"
		if crossing {
			name = "crossing_originals"
		}
		t.Run(name, func(t *testing.T) {
			h := newRTTTestContext(t, false, 0)
			h.exchange(h.mss, 10*time.Millisecond)
			h.clock.Advance(6 * time.Minute)
			start := h.sent
			advance := h.mss / 2
			if crossing {
				// Total ACK advancement equals the second original's size,
				// but covers the first byte and only a prefix of the second.
				// It must not be classified as a lone wholly ACKed runt.
				h.c.EP.SocketOptions().SetDelayOption(false)
				h.send(1)
				h.send(h.mss - 1)
				advance = h.mss - 1
			} else {
				h.send(h.mss)
			}
			h.clock.Advance(sampleRTT)
			st := h.ack(start+advance, 0)
			if got, want := h.c.Stack().Stats().TCP.Retransmits.Value(), uint64(0); got != want {
				t.Fatalf("retransmissions before partial ACK = %d, want %d", got, want)
			}
			if got, want := st.RACKState.ReoWnd, sampleRTT/4; got != want {
				t.Fatalf("partial ACK reorder window = %v, want %v", got, want)
			}
			h.clock.Advance(sampleRTT)
			st = h.ack(h.sent, 0)
			if got, want := h.c.Stack().Stats().TCP.Retransmits.Value(), uint64(0); got != want {
				t.Fatalf("retransmissions before remaining ACK = %d, want %d", got, want)
			}
			if got, want := st.RACKState.ReoWnd, sampleRTT/4; got != want {
				t.Fatalf("remaining ACK reorder window = %v, want %v", got, want)
			}
		})
	}
}

func TestMinimumRTTSelectiveACK(t *testing.T) {
	h := newRTTTestContext(t, false, 0)
	before := h.exchange(h.mss, 10*time.Millisecond)
	start := h.sent
	h.send(h.mss)
	h.clock.Advance(time.Millisecond)
	h.send(h.mss)
	h.clock.Advance(5 * time.Millisecond)
	st := h.ack(start, 0, header.SACKBlock{Start: h.c.IRS.Add(1 + seqnum.Size(start+h.mss)), End: h.c.IRS.Add(1 + seqnum.Size(h.sent))})
	if got, want := st.RACKState.ReoWnd, 1250*time.Microsecond; got != want {
		t.Fatalf("SACK reorder window = %v, want %v", got, want)
	}
	if got, want := st.RTTState, before.RTTState; got != want {
		t.Fatalf("SRTT state after SACK = %+v, want %+v", got, want)
	}
	h.ack(h.sent, 0)
	if got, want := h.c.Stack().Stats().TCP.Retransmits.Value(), uint64(0); got != want {
		t.Fatalf("retransmissions = %d, want %d", got, want)
	}
}

func TestMinimumRTTInterveningACK(t *testing.T) {
	h := newRTTTestContext(t, false, 0)
	h.exchange(h.mss, 10*time.Millisecond)
	h.clock.Advance(6 * time.Minute)
	// Explicitly allow two independent runt transmissions in flight. The
	// second ACK must not look like a lone runt sent after the first delivery.
	h.c.EP.SocketOptions().SetDelayOption(false)
	start := h.sent
	h.send(1)
	h.send(1)
	// ACK before the two-packet PTO at 20ms; the remaining packet then gets
	// the single-packet delayed-ACK allowance for its probe timeout.
	const ackInterval = 15 * time.Millisecond
	h.clock.Advance(ackInterval)
	st := h.ack(start+1, 0)
	if got, want := h.c.Stack().Stats().TCP.Retransmits.Value(), uint64(0); got != want {
		t.Fatalf("retransmissions before first ACK = %d, want %d", got, want)
	}
	if got, want := st.RACKState.ReoWnd, 2500*time.Microsecond; got != want {
		t.Fatalf("first runt reorder window = %v, want %v", got, want)
	}
	h.clock.Advance(ackInterval)
	st = h.ack(h.sent, 0)
	if got, want := h.c.Stack().Stats().TCP.Retransmits.Value(), uint64(0); got != want {
		t.Fatalf("retransmissions before second ACK = %d, want %d", got, want)
	}
	if got, want := st.RACKState.ReoWnd, ackInterval/2; got != want {
		t.Fatalf("second runt reorder window = %v, want %v", got, want)
	}
}

func TestMinimumRTTHandshake(t *testing.T) {
	h := newRTTTestContext(t, false, 10*time.Millisecond)
	st := h.exchange(h.mss, 100*time.Millisecond)
	if got, want := st.RACKState.ReoWnd, 2500*time.Microsecond; got != want {
		t.Fatalf("reorder window after handshake and data = %v, want %v", got, want)
	}
	if got, want := st.RTTState.SRTT, 21250*time.Microsecond; got != want {
		t.Fatalf("SRTT after handshake and data = %v, want %v", got, want)
	}
}
