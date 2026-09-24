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
