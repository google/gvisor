// Copyright 2018 The gVisor Authors.
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
	"encoding/binary"
	"fmt"
	"math"
	"time"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/hash/jenkins"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/waiter"
)

// InitialRTO is the initial retransmission timeout.
// https://github.com/torvalds/linux/blob/7c636d4d20f/include/net/tcp.h#L142
const InitialRTO = time.Second

// maxSegmentsPerWake is the maximum number of segments to process in the main
// protocol goroutine per wake-up. Yielding [after this number of segments are
// processed] allows other events to be processed as well (e.g., timeouts,
// resets, etc.).
const maxSegmentsPerWake = 100

type handshakeState int

// The following are the possible states of the TCP connection during a 3-way
// handshake. A depiction of the states and transitions can be found in RFC 793,
// page 23.
const (
	handshakeSynSent handshakeState = iota
	handshakeSynRcvd
	handshakeCompleted
)

const (
	// Maximum space available for options.
	maxOptionSize = 40
)

// handshake holds the state used during a TCP 3-way handshake.
//
// NOTE: handshake.ep.mu is held during handshake processing. It is released if
// we are going to block and reacquired when we start processing an event.
//
// +stateify savable
type handshake struct {
	ep       *endpoint
	listenEP *endpoint
	state    handshakeState
	active   bool
	flags    header.TCPFlags
	ackNum   seqnum.Value

	// iss is the initial send sequence number, as defined in RFC 793.
	iss seqnum.Value

	// rcvWnd is the receive window, as defined in RFC 793.
	rcvWnd seqnum.Size

	// sndWnd is the send window, as defined in RFC 793.
	sndWnd seqnum.Size

	// mss is the maximum segment size received from the peer.
	mss uint16

	// sndWndScale is the send window scale, as defined in RFC 1323. A
	// negative value means no scaling is supported by the peer.
	sndWndScale int

	// rcvWndScale is the receive window scale, as defined in RFC 1323.
	rcvWndScale int

	// startTime is the time at which the first SYN/SYN-ACK was sent.
	startTime tcpip.MonotonicTime

	// deferAccept if non-zero will drop the final ACK for a passive
	// handshake till an ACK segment with data is received or the timeout is
	// hit.
	deferAccept time.Duration

	// acked is true if the the final ACK for a 3-way handshake has
	// been received. This is required to stop retransmitting the
	// original SYN-ACK when deferAccept is enabled.
	acked bool

	// sendSYNOpts is the cached values for the SYN options to be sent.
	sendSYNOpts header.TCPSynOptions

	// sampleRTTWithTSOnly is true when the segment was retransmitted or we can't
	// tell; then RTT can only be sampled when the incoming segment has timestamp
	// options enabled.
	sampleRTTWithTSOnly bool

	// retransmitTimer is used to retransmit SYN/SYN-ACK with exponential backoff
	// till handshake is either completed or timesout.
	retransmitTimer *backoffTimer `state:"nosave"`
}

// maybeFailTimerHandler takes a handler function for a timer that may fail and
// returns a function that will invoke the provided handler with the endpoint
// mutex held. In addition the returned function will perform any cleanup that
// maybe required if the timer handler returns an error and in case of no errors
// will notify the processor if there are pending segments that need to be
// processed.

// NOTE: e.mu is held for the duration of the call to f().
func maybeFailTimerHandler(e *endpoint, f func() tcpip.Error) func() {
	return func() {
		e.mu.Lock()
		if err := f(); err != nil {
			e.lastErrorMu.Lock()
			// If the handler timed out and we have a lastError recorded (maybe due
			// to an ICMP message received), promote it to be the hard error.
			if _, isTimeout := err.(*tcpip.ErrTimeout); e.lastError != nil && isTimeout {
				e.hardError = e.lastError
			} else {
				e.hardError = err
			}
			e.lastError = err
			e.lastErrorMu.Unlock()
			e.cleanupLocked()
			e.setEndpointState(StateError)
			e.mu.Unlock()
			e.waiterQueue.Notify(waiter.EventHUp | waiter.EventErr | waiter.ReadableEvents | waiter.WritableEvents)
			return
		}
		processor := e.protocol.dispatcher.selectProcessor(e.ID)
		e.mu.Unlock()

		// notify processor if there are pending segments to be
		// processed.
		if !e.segmentQueue.empty() {
			processor.queueEndpoint(e)
		}
	}
}

// timerHandler takes a handler function for a timer that never results in a
// connection being aborted and returns a function that will invoke the provided
// handler with the endpoint mutex held. In addition the returned function will
// notify the processor if there are pending segments that need to be processed
// once the handler function completes.
//
// NOTE: e.mu is held for the duration of the call to f()
func timerHandler(e *endpoint, f func()) func() {
	return func() {
		e.mu.Lock()
		f()
		processor := e.protocol.dispatcher.selectProcessor(e.ID)
		e.mu.Unlock()
		// notify processor if there are pending segments to be
		// processed.
		if !e.segmentQueue.empty() {
			processor.queueEndpoint(e)
		}
	}
}

// +checklocks:e.mu
// +checklocksacquire:h.ep.mu
func (e *endpoint) newHandshake() (h *handshake) {
	h = &handshake{
		ep:          e,
		active:      true,
		rcvWnd:      seqnum.Size(e.initialReceiveWindow()),
		rcvWndScale: e.rcvWndScaleForHandshake(),
	}
	h.ep.AssertLockHeld(e)
	h.resetState()
	// Store reference to handshake state in endpoint.
	e.h = h
	// By the time handshake is created, e.ID is already initialized.
	e.TSOffset = e.protocol.tsOffset(e.ID.LocalAddress, e.ID.RemoteAddress)
	timer, err := newBackoffTimer(h.ep.stack.Clock(), InitialRTO, MaxRTO, maybeFailTimerHandler(e, h.retransmitHandlerLocked))
	if err != nil {
		panic(fmt.Sprintf("newBackOffTimer(_, %s, %s, _) failed: %s", InitialRTO, MaxRTO, err))
	}
	h.retransmitTimer = timer
	return h
}

// +checklocks:e.mu
// +checklocksacquire:h.ep.mu
func (e *endpoint) newPassiveHandshake(isn, irs seqnum.Value, opts header.TCPSynOptions, deferAccept time.Duration) (h *handshake) {
	h = e.newHandshake()
	h.resetToSynRcvd(isn, irs, opts, deferAccept)
	return h
}

// FindWndScale determines the window scale to use for the given maximum window
// size.
func FindWndScale(wnd seqnum.Size) int {
	if wnd < 0x10000 {
		return 0
	}

	max := seqnum.Size(math.MaxUint16)
	s := 0
	for wnd > max && s < header.MaxWndScale {
		s++
		max <<= 1
	}

	return s
}

// resetState resets the state of the handshake object such that it becomes
// ready for a new 3-way handshake.
func (h *handshake) resetState() {
	h.state = handshakeSynSent
	h.flags = header.TCPFlagSyn
	h.ackNum = 0
	h.mss = 0
	h.iss = generateSecureISN(h.ep.TransportEndpointInfo.ID, h.ep.stack.Clock(), h.ep.protocol.seqnumSecret)
}

// generateSecureISN generates a secure Initial Sequence number based on the
// recommendation here https://tools.ietf.org/html/rfc6528#page-3.
func generateSecureISN(id stack.TransportEndpointID, clock tcpip.Clock, seed uint32) seqnum.Value {
	isnHasher := jenkins.Sum32(seed)
	// Per hash.Hash.Writer:
	//
	// It never returns an error.
	_, _ = isnHasher.Write([]byte(id.LocalAddress))
	_, _ = isnHasher.Write([]byte(id.RemoteAddress))
	portBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(portBuf, id.LocalPort)
	_, _ = isnHasher.Write(portBuf)
	binary.LittleEndian.PutUint16(portBuf, id.RemotePort)
	_, _ = isnHasher.Write(portBuf)
	// The time period here is 64ns. This is similar to what linux uses
	// generate a sequence number that overlaps less than one
	// time per MSL (2 minutes).
	//
	// A 64ns clock ticks 10^9/64 = 15625000) times in a second.
	// To wrap the whole 32 bit space would require
	// 2^32/1562500 ~ 274 seconds.
	//
	// Which sort of guarantees that we won't reuse the ISN for a new
	// connection for the same tuple for at least 274s.
	isn := isnHasher.Sum32() + uint32(clock.NowMonotonic().Sub(tcpip.MonotonicTime{}).Nanoseconds()>>6)
	return seqnum.Value(isn)
}

// effectiveRcvWndScale returns the effective receive window scale to be used.
// If the peer doesn't support window scaling, the effective rcv wnd scale is
// zero; otherwise it's the value calculated based on the initial rcv wnd.
func (h *handshake) effectiveRcvWndScale() uint8 {
	if h.sndWndScale < 0 {
		return 0
	}
	return uint8(h.rcvWndScale)
}

// resetToSynRcvd resets the state of the handshake object to the SYN-RCVD
// state.
// +checklocks:h.ep.mu
func (h *handshake) resetToSynRcvd(iss seqnum.Value, irs seqnum.Value, opts header.TCPSynOptions, deferAccept time.Duration) {
	h.active = false
	h.state = handshakeSynRcvd
	h.flags = header.TCPFlagSyn | header.TCPFlagAck
	h.iss = iss
	h.ackNum = irs + 1
	h.mss = opts.MSS
	h.sndWndScale = opts.WS
	h.deferAccept = deferAccept
	h.ep.setEndpointState(StateSynRecv)
}

// checkAck checks if the ACK number, if present, of a segment received during
// a TCP 3-way handshake is valid. If it's not, a RST segment is sent back in
// response.
func (h *handshake) checkAck(s *segment) bool {
	if s.flags.Contains(header.TCPFlagAck) && s.ackNumber != h.iss+1 {
		// RFC 793, page 72 (https://datatracker.ietf.org/doc/html/rfc793#page-72):
		//   If the segment acknowledgment is not acceptable, form a reset segment,
		//        <SEQ=SEG.ACK><CTL=RST>
		//   and send it.
		h.ep.sendEmptyRaw(header.TCPFlagRst, s.ackNumber, 0, 0)
		return false
	}

	return true
}

// synSentState handles a segment received when the TCP 3-way handshake is in
// the SYN-SENT state.
// +checklocks:h.ep.mu
func (h *handshake) synSentState(s *segment) tcpip.Error {
	// RFC 793, page 37, states that in the SYN-SENT state, a reset is
	// acceptable if the ack field acknowledges the SYN.
	if s.flags.Contains(header.TCPFlagRst) {
		if s.flags.Contains(header.TCPFlagAck) && s.ackNumber == h.iss+1 {
			// RFC 793, page 67, states that "If the RST bit is set [and] If the ACK
			// was acceptable then signal the user "error: connection reset", drop
			// the segment, enter CLOSED state, delete TCB, and return."
			// Although the RFC above calls out ECONNRESET, Linux actually returns
			// ECONNREFUSED here so we do as well.
			return &tcpip.ErrConnectionRefused{}
		}
		return nil
	}

	if !h.checkAck(s) {
		return nil
	}

	// We are in the SYN-SENT state. We only care about segments that have
	// the SYN flag.
	if !s.flags.Contains(header.TCPFlagSyn) {
		return nil
	}

	// Parse the SYN options.
	rcvSynOpts := parseSynSegmentOptions(s)

	// Remember if the Timestamp option was negotiated.
	h.ep.maybeEnableTimestamp(rcvSynOpts)

	// Remember if the SACKPermitted option was negotiated.
	h.ep.maybeEnableSACKPermitted(rcvSynOpts)

	// Remember the sequence we'll ack from now on.
	h.ackNum = s.sequenceNumber + 1
	h.flags |= header.TCPFlagAck
	h.mss = rcvSynOpts.MSS
	h.sndWndScale = rcvSynOpts.WS

	// If this is a SYN ACK response, we only need to acknowledge the SYN
	// and the handshake is completed.
	if s.flags.Contains(header.TCPFlagAck) {
		h.state = handshakeCompleted
		h.transitionToStateEstablishedLocked(s)

		h.ep.sendEmptyRaw(header.TCPFlagAck, h.iss+1, h.ackNum, h.rcvWnd>>h.effectiveRcvWndScale())
		return nil
	}

	// A SYN segment was received, but no ACK in it. We acknowledge the SYN
	// but resend our own SYN and wait for it to be acknowledged in the
	// SYN-RCVD state.
	h.state = handshakeSynRcvd
	ttl := calculateTTL(h.ep.route, h.ep.ipv4TTL, h.ep.ipv6HopLimit)
	amss := h.ep.amss
	h.ep.setEndpointState(StateSynRecv)
	synOpts := header.TCPSynOptions{
		WS:    int(h.effectiveRcvWndScale()),
		TS:    rcvSynOpts.TS,
		TSVal: h.ep.tsValNow(),
		TSEcr: h.ep.recentTimestamp(),

		// We only send SACKPermitted if the other side indicated it
		// permits SACK. This is not explicitly defined in the RFC but
		// this is the behaviour implemented by Linux.
		SACKPermitted: rcvSynOpts.SACKPermitted,
		MSS:           amss,
	}
	if ttl == 0 {
		ttl = h.ep.route.DefaultTTL()
	}
	h.ep.sendSynTCP(h.ep.route, tcpFields{
		id:     h.ep.TransportEndpointInfo.ID,
		ttl:    ttl,
		tos:    h.ep.sendTOS,
		flags:  h.flags,
		seq:    h.iss,
		ack:    h.ackNum,
		rcvWnd: h.rcvWnd,
	}, synOpts)
	return nil
}

// synRcvdState handles a segment received when the TCP 3-way handshake is in
// the SYN-RCVD state.
// +checklocks:h.ep.mu
func (h *handshake) synRcvdState(s *segment) tcpip.Error {
	if s.flags.Contains(header.TCPFlagRst) {
		// RFC 793, page 37, states that in the SYN-RCVD state, a reset
		// is acceptable if the sequence number is in the window.
		if s.sequenceNumber.InWindow(h.ackNum, h.rcvWnd) {
			return &tcpip.ErrConnectionRefused{}
		}
		return nil
	}

	if !h.checkAck(s) {
		return nil
	}

	// RFC 793, Section 3.9, page 69, states that in the SYN-RCVD state, a
	// sequence number outside of the window causes an ACK with the proper seq
	// number and "After sending the acknowledgment, drop the unacceptable
	// segment and return."
	if !s.sequenceNumber.InWindow(h.ackNum, h.rcvWnd) {
		if h.ep.allowOutOfWindowAck() {
			h.ep.sendEmptyRaw(header.TCPFlagAck, h.iss+1, h.ackNum, h.rcvWnd)
		}
		return nil
	}

	if s.flags.Contains(header.TCPFlagSyn) && s.sequenceNumber != h.ackNum-1 {
		// We received two SYN segments with different sequence
		// numbers, so we reset this and restart the whole
		// process, except that we don't reset the timer.
		ack := s.sequenceNumber.Add(s.logicalLen())
		seq := seqnum.Value(0)
		if s.flags.Contains(header.TCPFlagAck) {
			seq = s.ackNumber
		}
		h.ep.sendEmptyRaw(header.TCPFlagRst|header.TCPFlagAck, seq, ack, 0)

		if !h.active {
			return &tcpip.ErrInvalidEndpointState{}
		}

		h.resetState()
		synOpts := header.TCPSynOptions{
			WS:            h.rcvWndScale,
			TS:            h.ep.SendTSOk,
			TSVal:         h.ep.tsValNow(),
			TSEcr:         h.ep.recentTimestamp(),
			SACKPermitted: h.ep.SACKPermitted,
			MSS:           h.ep.amss,
		}
		h.ep.sendSynTCP(h.ep.route, tcpFields{
			id:     h.ep.TransportEndpointInfo.ID,
			ttl:    calculateTTL(h.ep.route, h.ep.ipv4TTL, h.ep.ipv6HopLimit),
			tos:    h.ep.sendTOS,
			flags:  h.flags,
			seq:    h.iss,
			ack:    h.ackNum,
			rcvWnd: h.rcvWnd,
		}, synOpts)
		return nil
	}

	// We have previously received (and acknowledged) the peer's SYN. If the
	// peer acknowledges our SYN, the handshake is completed.
	if s.flags.Contains(header.TCPFlagAck) {
		// If deferAccept is not zero and this is a bare ACK and the
		// timeout is not hit then drop the ACK.
		if h.deferAccept != 0 && s.payloadSize() == 0 && h.ep.stack.Clock().NowMonotonic().Sub(h.startTime) < h.deferAccept {
			h.acked = true
			h.ep.stack.Stats().DroppedPackets.Increment()
			return nil
		}

		// If the timestamp option is negotiated and the segment does
		// not carry a timestamp option then the segment must be dropped
		// as per https://tools.ietf.org/html/rfc7323#section-3.2.
		if h.ep.SendTSOk && !s.parsedOptions.TS {
			h.ep.stack.Stats().DroppedPackets.Increment()
			return nil
		}

		// Drop the ACK if the accept queue is full.
		// https://github.com/torvalds/linux/blob/7acac4b3196/net/ipv4/tcp_ipv4.c#L1523
		// We could abort the connection as well with a tunable as in
		// https://github.com/torvalds/linux/blob/7acac4b3196/net/ipv4/tcp_minisocks.c#L788
		if listenEP := h.listenEP; listenEP != nil && listenEP.acceptQueueIsFull() {
			listenEP.stack.Stats().DroppedPackets.Increment()
			return nil
		}

		// Update timestamp if required. See RFC7323, section-4.3.
		if h.ep.SendTSOk && s.parsedOptions.TS {
			h.ep.updateRecentTimestamp(s.parsedOptions.TSVal, h.ackNum, s.sequenceNumber)
		}

		h.state = handshakeCompleted
		h.transitionToStateEstablishedLocked(s)

		// Requeue the segment if the ACK completing the handshake has more info
		// to be processed by the newly established endpoint.
		if (s.flags.Contains(header.TCPFlagFin) || s.payloadSize() > 0) && h.ep.enqueueSegment(s) {
			h.ep.protocol.dispatcher.selectProcessor(h.ep.ID).queueEndpoint(h.ep)

		}
		return nil
	}

	return nil
}

// +checklocks:h.ep.mu
func (h *handshake) handleSegment(s *segment) tcpip.Error {
	h.sndWnd = s.window
	if !s.flags.Contains(header.TCPFlagSyn) && h.sndWndScale > 0 {
		h.sndWnd <<= uint8(h.sndWndScale)
	}

	switch h.state {
	case handshakeSynRcvd:
		return h.synRcvdState(s)
	case handshakeSynSent:
		return h.synSentState(s)
	}
	return nil
}

// processSegments goes through the segment queue and processes up to
// maxSegmentsPerWake (if they're available).
// +checklocks:h.ep.mu
func (h *handshake) processSegments() tcpip.Error {
	for i := 0; i < maxSegmentsPerWake; i++ {
		s := h.ep.segmentQueue.dequeue()
		if s == nil {
			return nil
		}

		err := h.handleSegment(s)
		s.DecRef()
		if err != nil {
			return err
		}

		// We stop processing packets once the handshake is completed,
		// otherwise we may process packets meant to be processed by
		// the main protocol goroutine.
		if h.state == handshakeCompleted {
			break
		}
	}

	return nil
}

// start sends the first SYN/SYN-ACK. It does not block, even if link address
// resolution is required.
func (h *handshake) start() {
	h.startTime = h.ep.stack.Clock().NowMonotonic()
	h.ep.amss = calculateAdvertisedMSS(h.ep.userMSS, h.ep.route)
	var sackEnabled tcpip.TCPSACKEnabled
	if err := h.ep.stack.TransportProtocolOption(ProtocolNumber, &sackEnabled); err != nil {
		// If stack returned an error when checking for SACKEnabled
		// status then just default to switching off SACK negotiation.
		sackEnabled = false
	}

	synOpts := header.TCPSynOptions{
		WS:            h.rcvWndScale,
		TS:            true,
		TSVal:         h.ep.tsValNow(),
		TSEcr:         h.ep.recentTimestamp(),
		SACKPermitted: bool(sackEnabled),
		MSS:           h.ep.amss,
	}

	// start() is also called in a listen context so we want to make sure we only
	// send the TS/SACK option when we received the TS/SACK in the initial SYN.
	if h.state == handshakeSynRcvd {
		synOpts.TS = h.ep.SendTSOk
		synOpts.SACKPermitted = h.ep.SACKPermitted && bool(sackEnabled)
		if h.sndWndScale < 0 {
			// Disable window scaling if the peer did not send us
			// the window scaling option.
			synOpts.WS = -1
		}
	}

	h.sendSYNOpts = synOpts
	h.ep.sendSynTCP(h.ep.route, tcpFields{
		id:     h.ep.TransportEndpointInfo.ID,
		ttl:    calculateTTL(h.ep.route, h.ep.ipv4TTL, h.ep.ipv6HopLimit),
		tos:    h.ep.sendTOS,
		flags:  h.flags,
		seq:    h.iss,
		ack:    h.ackNum,
		rcvWnd: h.rcvWnd,
	}, synOpts)
}

// retransmitHandler handles retransmissions of un-acked SYNs.
// +checklocks:h.ep.mu
func (h *handshake) retransmitHandlerLocked() tcpip.Error {
	e := h.ep
	// If the endpoint has already transition out of a connecting state due
	// to say an error (e.g) peer send RST or an ICMP error. Then just
	// return. Any required cleanup should have been done when the RST/error
	// was handled.
	if !e.EndpointState().connecting() {
		return nil
	}

	if err := h.retransmitTimer.reset(); err != nil {
		return err
	}

	// Resend the SYN/SYN-ACK only if the following conditions hold.
	//  - It's an active handshake (deferAccept does not apply)
	//  - It's a passive handshake and we have not yet got the final-ACK.
	//  - It's a passive handshake and we got an ACK but deferAccept is
	//    enabled and we are now past the deferAccept duration.
	// The last is required to provide a way for the peer to complete
	// the connection with another ACK or data (as ACKs are never
	// retransmitted on their own).
	if h.active || !h.acked || h.deferAccept != 0 && e.stack.Clock().NowMonotonic().Sub(h.startTime) > h.deferAccept {
		e.sendSynTCP(e.route, tcpFields{
			id:     e.TransportEndpointInfo.ID,
			ttl:    calculateTTL(e.route, e.ipv4TTL, e.ipv6HopLimit),
			tos:    e.sendTOS,
			flags:  h.flags,
			seq:    h.iss,
			ack:    h.ackNum,
			rcvWnd: h.rcvWnd,
		}, h.sendSYNOpts)
		// If we have ever retransmitted the SYN-ACK or
		// SYN segment, we should only measure RTT if
		// TS option is present.
		h.sampleRTTWithTSOnly = true
	}
	return nil
}

// transitionToStateEstablisedLocked transitions the endpoint of the handshake
// to an established state given the last segment received from peer. It also
// initializes sender/receiver.
// +checklocks:h.ep.mu
func (h *handshake) transitionToStateEstablishedLocked(s *segment) {
	// Stop the SYN retransmissions now that handshake is complete.
	if h.retransmitTimer != nil {
		h.retransmitTimer.stop()
	}

	// Transfer handshake state to TCP connection. We disable
	// receive window scaling if the peer doesn't support it
	// (indicated by a negative send window scale).
	h.ep.snd = newSender(h.ep, h.iss, h.ackNum-1, h.sndWnd, h.mss, h.sndWndScale)

	now := h.ep.stack.Clock().NowMonotonic()

	var rtt time.Duration
	if h.ep.SendTSOk && s.parsedOptions.TSEcr != 0 {
		rtt = h.ep.elapsed(now, s.parsedOptions.TSEcr)
	}
	if !h.sampleRTTWithTSOnly && rtt == 0 {
		rtt = now.Sub(h.startTime)
	}

	if rtt > 0 {
		h.ep.snd.updateRTO(rtt)
	}

	h.ep.rcvQueueMu.Lock()
	h.ep.rcv = newReceiver(h.ep, h.ackNum-1, h.rcvWnd, h.effectiveRcvWndScale())
	// Bootstrap the auto tuning algorithm. Starting at zero will
	// result in a really large receive window after the first auto
	// tuning adjustment.
	h.ep.RcvAutoParams.PrevCopiedBytes = int(h.rcvWnd)
	h.ep.rcvQueueMu.Unlock()

	h.ep.setEndpointState(StateEstablished)

	// Completing the 3-way handshake is an indication that the route is valid
	// and the remote is reachable as the only way we can complete a handshake
	// is if our SYN reached the remote and their ACK reached us.
	h.ep.route.ConfirmReachable()

	// Tell waiters that the endpoint is connected and writable.
	h.ep.waiterQueue.Notify(waiter.WritableEvents)
}

type backoffTimer struct {
	timeout    time.Duration
	maxTimeout time.Duration
	t          tcpip.Timer
}

func newBackoffTimer(clock tcpip.Clock, timeout, maxTimeout time.Duration, f func()) (*backoffTimer, tcpip.Error) {
	if timeout > maxTimeout {
		return nil, &tcpip.ErrTimeout{}
	}
	bt := &backoffTimer{timeout: timeout, maxTimeout: maxTimeout}
	bt.t = clock.AfterFunc(timeout, f)
	return bt, nil
}

func (bt *backoffTimer) reset() tcpip.Error {
	bt.timeout *= 2
	if bt.timeout > bt.maxTimeout {
		return &tcpip.ErrTimeout{}
	}
	bt.t.Reset(bt.timeout)
	return nil
}

func (bt *backoffTimer) stop() {
	bt.t.Stop()
}

func parseSynSegmentOptions(s *segment) header.TCPSynOptions {
	synOpts := header.ParseSynOptions(s.options, s.flags.Contains(header.TCPFlagAck))
	if synOpts.TS {
		s.parsedOptions.TSVal = synOpts.TSVal
		s.parsedOptions.TSEcr = synOpts.TSEcr
	}
	return synOpts
}

var optionPool = sync.Pool{
	New: func() any {
		return &[maxOptionSize]byte{}
	},
}

func getOptions() []byte {
	return (*optionPool.Get().(*[maxOptionSize]byte))[:]
}

func putOptions(options []byte) {
	// Reslice to full capacity.
	optionPool.Put(optionsToArray(options))
}

func makeSynOptions(opts header.TCPSynOptions) []byte {
	// Emulate linux option order. This is as follows:
	//
	// if md5: NOP NOP MD5SIG 18 md5sig(16)
	// if mss: MSS 4 mss(2)
	// if ts and sack_advertise:
	//	SACK 2 TIMESTAMP 2 timestamp(8)
	// elif ts: NOP NOP TIMESTAMP 10 timestamp(8)
	// elif sack: NOP NOP SACK 2
	// if wscale: NOP WINDOW 3 ws(1)
	// if sack_blocks: NOP NOP SACK ((2 + (#blocks * 8))
	//	[for each block] start_seq(4) end_seq(4)
	// if fastopen_cookie:
	//	if exp: EXP (4 + len(cookie)) FASTOPEN_MAGIC(2)
	// 	else: FASTOPEN (2 + len(cookie))
	//	cookie(variable) [padding to four bytes]
	//
	options := getOptions()

	// Always encode the mss.
	offset := header.EncodeMSSOption(uint32(opts.MSS), options)

	// Special ordering is required here. If both TS and SACK are enabled,
	// then the SACK option precedes TS, with no padding. If they are
	// enabled individually, then we see padding before the option.
	if opts.TS && opts.SACKPermitted {
		offset += header.EncodeSACKPermittedOption(options[offset:])
		offset += header.EncodeTSOption(opts.TSVal, opts.TSEcr, options[offset:])
	} else if opts.TS {
		offset += header.EncodeNOP(options[offset:])
		offset += header.EncodeNOP(options[offset:])
		offset += header.EncodeTSOption(opts.TSVal, opts.TSEcr, options[offset:])
	} else if opts.SACKPermitted {
		offset += header.EncodeNOP(options[offset:])
		offset += header.EncodeNOP(options[offset:])
		offset += header.EncodeSACKPermittedOption(options[offset:])
	}

	// Initialize the WS option.
	if opts.WS >= 0 {
		offset += header.EncodeNOP(options[offset:])
		offset += header.EncodeWSOption(opts.WS, options[offset:])
	}

	// Padding to the end; note that this never apply unless we add a
	// fastopen option, we always expect the offset to remain the same.
	if delta := header.AddTCPOptionPadding(options, offset); delta != 0 {
		panic("unexpected option encoding")
	}

	return options[:offset]
}

// tcpFields is a struct to carry different parameters required by the
// send*TCP variant functions below.
type tcpFields struct {
	id     stack.TransportEndpointID
	ttl    uint8
	tos    uint8
	flags  header.TCPFlags
	seq    seqnum.Value
	ack    seqnum.Value
	rcvWnd seqnum.Size
	opts   []byte
	txHash uint32
}

func (e *endpoint) sendSynTCP(r *stack.Route, tf tcpFields, opts header.TCPSynOptions) tcpip.Error {
	tf.opts = makeSynOptions(opts)
	// We ignore SYN send errors and let the callers re-attempt send.
	p := stack.NewPacketBuffer(stack.PacketBufferOptions{ReserveHeaderBytes: header.TCPMinimumSize + int(r.MaxHeaderLength()) + len(tf.opts)})
	defer p.DecRef()
	if err := e.sendTCP(r, tf, p, stack.GSO{}); err != nil {
		e.stats.SendErrors.SynSendToNetworkFailed.Increment()
	}
	putOptions(tf.opts)
	return nil
}

// This method takes ownership of pkt.
func (e *endpoint) sendTCP(r *stack.Route, tf tcpFields, pkt stack.PacketBufferPtr, gso stack.GSO) tcpip.Error {
	tf.txHash = e.txHash
	if err := sendTCP(r, tf, pkt, gso, e.owner); err != nil {
		e.stats.SendErrors.SegmentSendToNetworkFailed.Increment()
		return err
	}
	e.stats.SegmentsSent.Increment()
	return nil
}

func buildTCPHdr(r *stack.Route, tf tcpFields, pkt stack.PacketBufferPtr, gso stack.GSO) {
	optLen := len(tf.opts)
	tcp := header.TCP(pkt.TransportHeader().Push(header.TCPMinimumSize + optLen))
	pkt.TransportProtocolNumber = header.TCPProtocolNumber
	tcp.Encode(&header.TCPFields{
		SrcPort:    tf.id.LocalPort,
		DstPort:    tf.id.RemotePort,
		SeqNum:     uint32(tf.seq),
		AckNum:     uint32(tf.ack),
		DataOffset: uint8(header.TCPMinimumSize + optLen),
		Flags:      tf.flags,
		WindowSize: uint16(tf.rcvWnd),
	})
	copy(tcp[header.TCPMinimumSize:], tf.opts)

	xsum := r.PseudoHeaderChecksum(ProtocolNumber, uint16(pkt.Size()))
	// Only calculate the checksum if offloading isn't supported.
	if gso.Type != stack.GSONone && gso.NeedsCsum {
		// This is called CHECKSUM_PARTIAL in the Linux kernel. We
		// calculate a checksum of the pseudo-header and save it in the
		// TCP header, then the kernel calculate a checksum of the
		// header and data and get the right sum of the TCP packet.
		tcp.SetChecksum(xsum)
	} else if r.RequiresTXTransportChecksum() {
		xsum = checksum.Combine(xsum, pkt.Data().Checksum())
		tcp.SetChecksum(^tcp.CalculateChecksum(xsum))
	}
}

func sendTCPBatch(r *stack.Route, tf tcpFields, pkt stack.PacketBufferPtr, gso stack.GSO, owner tcpip.PacketOwner) tcpip.Error {
	optLen := len(tf.opts)
	if tf.rcvWnd > math.MaxUint16 {
		tf.rcvWnd = math.MaxUint16
	}

	mss := int(gso.MSS)
	n := (pkt.Data().Size() + mss - 1) / mss

	size := pkt.Data().Size()
	hdrSize := header.TCPMinimumSize + int(r.MaxHeaderLength()) + optLen
	for i := 0; i < n; i++ {
		packetSize := mss
		if packetSize > size {
			packetSize = size
		}
		size -= packetSize

		pkt := pkt
		// No need to split the packet in the final iteration. The original
		// packet already has the truncated data.
		shouldSplitPacket := i != n-1
		if shouldSplitPacket {
			splitPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{ReserveHeaderBytes: hdrSize})
			splitPkt.Data().ReadFromPacketData(pkt.Data(), packetSize)
			pkt = splitPkt
		}
		pkt.Hash = tf.txHash
		pkt.Owner = owner

		buildTCPHdr(r, tf, pkt, gso)
		tf.seq = tf.seq.Add(seqnum.Size(packetSize))
		pkt.GSOOptions = gso
		if err := r.WritePacket(stack.NetworkHeaderParams{Protocol: ProtocolNumber, TTL: tf.ttl, TOS: tf.tos}, pkt); err != nil {
			r.Stats().TCP.SegmentSendErrors.Increment()
			if shouldSplitPacket {
				pkt.DecRef()
			}
			return err
		}
		r.Stats().TCP.SegmentsSent.Increment()
		if shouldSplitPacket {
			pkt.DecRef()
		}
	}
	return nil
}

// sendTCP sends a TCP segment with the provided options via the provided
// network endpoint and under the provided identity. This method takes
// ownership of pkt.
func sendTCP(r *stack.Route, tf tcpFields, pkt stack.PacketBufferPtr, gso stack.GSO, owner tcpip.PacketOwner) tcpip.Error {
	if tf.rcvWnd > math.MaxUint16 {
		tf.rcvWnd = math.MaxUint16
	}

	if r.Loop()&stack.PacketLoop == 0 && gso.Type == stack.GSOGvisor && int(gso.MSS) < pkt.Data().Size() {
		return sendTCPBatch(r, tf, pkt, gso, owner)
	}

	pkt.GSOOptions = gso
	pkt.Hash = tf.txHash
	pkt.Owner = owner
	buildTCPHdr(r, tf, pkt, gso)

	if err := r.WritePacket(stack.NetworkHeaderParams{Protocol: ProtocolNumber, TTL: tf.ttl, TOS: tf.tos}, pkt); err != nil {
		r.Stats().TCP.SegmentSendErrors.Increment()
		return err
	}
	r.Stats().TCP.SegmentsSent.Increment()
	if (tf.flags & header.TCPFlagRst) != 0 {
		r.Stats().TCP.ResetsSent.Increment()
	}
	return nil
}

// makeOptions makes an options slice.
func (e *endpoint) makeOptions(sackBlocks []header.SACKBlock) []byte {
	options := getOptions()
	offset := 0

	// N.B. the ordering here matches the ordering used by Linux internally
	// and described in the raw makeOptions function. We don't include
	// unnecessary cases here (post connection.)
	if e.SendTSOk {
		// Embed the timestamp if timestamp has been enabled.
		//
		// We only use the lower 32 bits of the unix time in
		// milliseconds. This is similar to what Linux does where it
		// uses the lower 32 bits of the jiffies value in the tsVal
		// field of the timestamp option.
		//
		// Further, RFC7323 section-5.4 recommends millisecond
		// resolution as the lowest recommended resolution for the
		// timestamp clock.
		//
		// Ref: https://tools.ietf.org/html/rfc7323#section-5.4.
		offset += header.EncodeNOP(options[offset:])
		offset += header.EncodeNOP(options[offset:])
		offset += header.EncodeTSOption(e.tsValNow(), e.recentTimestamp(), options[offset:])
	}
	if e.SACKPermitted && len(sackBlocks) > 0 {
		offset += header.EncodeNOP(options[offset:])
		offset += header.EncodeNOP(options[offset:])
		offset += header.EncodeSACKBlocks(sackBlocks, options[offset:])
	}

	// We expect the above to produce an aligned offset.
	if delta := header.AddTCPOptionPadding(options, offset); delta != 0 {
		panic("unexpected option encoding")
	}

	return options[:offset]
}

// sendEmptyRaw sends a TCP segment with no payload to the endpoint's peer.
func (e *endpoint) sendEmptyRaw(flags header.TCPFlags, seq, ack seqnum.Value, rcvWnd seqnum.Size) tcpip.Error {
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{})
	defer pkt.DecRef()
	return e.sendRaw(pkt, flags, seq, ack, rcvWnd)
}

// sendRaw sends a TCP segment to the endpoint's peer. This method takes
// ownership of pkt. pkt must not have any headers set.
func (e *endpoint) sendRaw(pkt stack.PacketBufferPtr, flags header.TCPFlags, seq, ack seqnum.Value, rcvWnd seqnum.Size) tcpip.Error {
	var sackBlocks []header.SACKBlock
	if e.EndpointState() == StateEstablished && e.rcv.pendingRcvdSegments.Len() > 0 && (flags&header.TCPFlagAck != 0) {
		sackBlocks = e.sack.Blocks[:e.sack.NumBlocks]
	}
	options := e.makeOptions(sackBlocks)
	defer putOptions(options)
	pkt.ReserveHeaderBytes(header.TCPMinimumSize + int(e.route.MaxHeaderLength()) + len(options))
	return e.sendTCP(e.route, tcpFields{
		id:     e.TransportEndpointInfo.ID,
		ttl:    calculateTTL(e.route, e.ipv4TTL, e.ipv6HopLimit),
		tos:    e.sendTOS,
		flags:  flags,
		seq:    seq,
		ack:    ack,
		rcvWnd: rcvWnd,
		opts:   options,
	}, pkt, e.gso)
}

// +checklocks:e.mu
// +checklocksalias:e.snd.ep.mu=e.mu
func (e *endpoint) sendData(next *segment) {
	// Initialize the next segment to write if it's currently nil.
	if e.snd.writeNext == nil {
		if next == nil {
			return
		}
		e.snd.updateWriteNext(next)
	}

	// Push out any new packets.
	e.snd.sendData()
}

// resetConnectionLocked puts the endpoint in an error state with the given
// error code and sends a RST if and only if the error is not ErrConnectionReset
// indicating that the connection is being reset due to receiving a RST. This
// method must only be called from the protocol goroutine.
// +checklocks:e.mu
func (e *endpoint) resetConnectionLocked(err tcpip.Error) {
	// Only send a reset if the connection is being aborted for a reason
	// other than receiving a reset.
	e.hardError = err
	switch err.(type) {
	case *tcpip.ErrConnectionReset, *tcpip.ErrTimeout:
	default:
		// The exact sequence number to be used for the RST is the same as the
		// one used by Linux. We need to handle the case of window being shrunk
		// which can cause sndNxt to be outside the acceptable window on the
		// receiver.
		//
		// See: https://www.snellman.net/blog/archive/2016-02-01-tcp-rst/ for more
		// information.
		sndWndEnd := e.snd.SndUna.Add(e.snd.SndWnd)
		resetSeqNum := sndWndEnd
		if !sndWndEnd.LessThan(e.snd.SndNxt) || e.snd.SndNxt.Size(sndWndEnd) < (1<<e.snd.SndWndScale) {
			resetSeqNum = e.snd.SndNxt
		}
		e.sendEmptyRaw(header.TCPFlagAck|header.TCPFlagRst, resetSeqNum, e.rcv.RcvNxt, 0)
	}
	// Don't purge read queues here. If there's buffered data, it's still allowed
	// to be read.
	e.purgeWriteQueue()
	e.purgePendingRcvQueue()
	e.cleanupLocked()
	e.setEndpointState(StateError)
}

// transitionToStateCloseLocked ensures that the endpoint is
// cleaned up from the transport demuxer, "before" moving to
// StateClose. This will ensure that no packet will be
// delivered to this endpoint from the demuxer when the endpoint
// is transitioned to StateClose.
// +checklocks:e.mu
func (e *endpoint) transitionToStateCloseLocked() {
	s := e.EndpointState()
	if s == StateClose {
		return
	}

	if s.connected() {
		e.stack.Stats().TCP.EstablishedClosed.Increment()
	}

	e.cleanupLocked()
	// Mark the endpoint as fully closed for reads/writes.
	e.setEndpointState(StateClose)
}

// tryDeliverSegmentFromClosedEndpoint attempts to deliver the parsed
// segment to any other endpoint other than the current one. This is called
// only when the endpoint is in StateClose and we want to deliver the segment
// to any other listening endpoint. We reply with RST if we cannot find one.
func (e *endpoint) tryDeliverSegmentFromClosedEndpoint(s *segment) {
	ep := e.stack.FindTransportEndpoint(e.NetProto, e.TransProto, e.TransportEndpointInfo.ID, s.pkt.NICID)
	if ep == nil && e.NetProto == header.IPv6ProtocolNumber && e.TransportEndpointInfo.ID.LocalAddress.To4() != "" {
		// Dual-stack socket, try IPv4.
		ep = e.stack.FindTransportEndpoint(
			header.IPv4ProtocolNumber,
			e.TransProto,
			e.TransportEndpointInfo.ID,
			s.pkt.NICID,
		)
	}
	if ep == nil {
		if !s.flags.Contains(header.TCPFlagRst) {
			replyWithReset(e.stack, s, stack.DefaultTOS, tcpip.UseDefaultIPv4TTL, tcpip.UseDefaultIPv6HopLimit)
		}
		return
	}

	if e == ep {
		panic(fmt.Sprintf("current endpoint not removed from demuxer, enqueing segments to itself, endpoint in state %v", e.EndpointState()))
	}

	if ep := ep.(*endpoint); ep.enqueueSegment(s) {
		ep.notifyProcessor()
	}
}

// Drain segment queue from the endpoint and try to re-match the segment to a
// different endpoint. This is used when the current endpoint is transitioned to
// StateClose and has been unregistered from the transport demuxer.
func (e *endpoint) drainClosingSegmentQueue() {
	for {
		s := e.segmentQueue.dequeue()
		if s == nil {
			break
		}

		e.tryDeliverSegmentFromClosedEndpoint(s)
		s.DecRef()
	}
}

// +checklocks:e.mu
func (e *endpoint) handleReset(s *segment) (ok bool, err tcpip.Error) {
	if e.rcv.acceptable(s.sequenceNumber, 0) {
		// RFC 793, page 37 states that "in all states
		// except SYN-SENT, all reset (RST) segments are
		// validated by checking their SEQ-fields." So
		// we only process it if it's acceptable.
		switch e.EndpointState() {
		// In case of a RST in CLOSE-WAIT linux moves
		// the socket to closed state with an error set
		// to indicate EPIPE.
		//
		// Technically this seems to be at odds w/ RFC.
		// As per https://tools.ietf.org/html/rfc793#section-2.7
		// page 69 the behavior for a segment arriving
		// w/ RST bit set in CLOSE-WAIT is inlined below.
		//
		//  ESTABLISHED
		//  FIN-WAIT-1
		//  FIN-WAIT-2
		//  CLOSE-WAIT

		//  If the RST bit is set then, any outstanding RECEIVEs and
		//  SEND should receive "reset" responses. All segment queues
		//  should be flushed.  Users should also receive an unsolicited
		//  general "connection reset" signal. Enter the CLOSED state,
		//  delete the TCB, and return.
		case StateCloseWait:
			e.transitionToStateCloseLocked()
			e.hardError = &tcpip.ErrAborted{}
			return false, nil
		default:
			// RFC 793, page 37 states that "in all states
			// except SYN-SENT, all reset (RST) segments are
			// validated by checking their SEQ-fields." So
			// we only process it if it's acceptable.

			// Notify protocol goroutine. This is required when
			// handleSegment is invoked from the processor goroutine
			// rather than the worker goroutine.
			return false, &tcpip.ErrConnectionReset{}
		}
	}
	return true, nil
}

// handleSegments processes all inbound segments.
//
// +checklocks:e.mu
// +checklocksalias:e.snd.ep.mu=e.mu
func (e *endpoint) handleSegmentsLocked() tcpip.Error {
	sndUna := e.snd.SndUna
	for i := 0; i < maxSegmentsPerWake; i++ {
		if state := e.EndpointState(); state.closed() || state == StateTimeWait || state == StateError {
			return nil
		}
		s := e.segmentQueue.dequeue()
		if s == nil {
			break
		}
		cont, err := e.handleSegmentLocked(s)
		s.DecRef()
		if err != nil {
			return err
		}
		if !cont {
			return nil
		}
	}

	// The remote ACK-ing at least 1 byte is an indication that we have a
	// full-duplex connection to the remote as the only way we will receive an
	// ACK is if the remote received data that we previously sent.
	//
	// As of writing, Linux seems to only confirm a route as reachable when
	// forward progress is made which is indicated by an ACK that removes data
	// from the retransmit queue, i.e. sender makes forward progress.
	if sndUna.LessThan(e.snd.SndUna) {
		e.route.ConfirmReachable()
	}

	// Send an ACK for all processed packets if needed.
	if e.rcv.RcvNxt != e.snd.MaxSentAck {
		e.snd.sendAck()
	}

	e.resetKeepaliveTimer(true /* receivedData */)

	return nil
}

// +checklocks:e.mu
func (e *endpoint) probeSegmentLocked() {
	if fn := e.probe; fn != nil {
		var state stack.TCPEndpointState
		e.completeStateLocked(&state)
		fn(&state)
	}
}

// handleSegment handles a given segment and notifies the worker goroutine if
// if the connection should be terminated.
//
// +checklocks:e.mu
// +checklocksalias:e.rcv.ep.mu=e.mu
// +checklocksalias:e.snd.ep.mu=e.mu
func (e *endpoint) handleSegmentLocked(s *segment) (cont bool, err tcpip.Error) {
	// Invoke the tcp probe if installed. The tcp probe function will update
	// the TCPEndpointState after the segment is processed.
	defer e.probeSegmentLocked()

	if s.flags.Contains(header.TCPFlagRst) {
		if ok, err := e.handleReset(s); !ok {
			return false, err
		}
	} else if s.flags.Contains(header.TCPFlagSyn) {
		// See: https://tools.ietf.org/html/rfc5961#section-4.1
		//   1) If the SYN bit is set, irrespective of the sequence number, TCP
		//    MUST send an ACK (also referred to as challenge ACK) to the remote
		//    peer:
		//
		//    <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
		//
		//    After sending the acknowledgment, TCP MUST drop the unacceptable
		//    segment and stop processing further.
		//
		// By sending an ACK, the remote peer is challenged to confirm the loss
		// of the previous connection and the request to start a new connection.
		// A legitimate peer, after restart, would not have a TCB in the
		// synchronized state.  Thus, when the ACK arrives, the peer should send
		// a RST segment back with the sequence number derived from the ACK
		// field that caused the RST.

		// This RST will confirm that the remote peer has indeed closed the
		// previous connection.  Upon receipt of a valid RST, the local TCP
		// endpoint MUST terminate its connection.  The local TCP endpoint
		// should then rely on SYN retransmission from the remote end to
		// re-establish the connection.
		e.snd.maybeSendOutOfWindowAck(s)
	} else if s.flags.Contains(header.TCPFlagAck) {
		// Patch the window size in the segment according to the
		// send window scale.
		s.window <<= e.snd.SndWndScale

		// RFC 793, page 41 states that "once in the ESTABLISHED
		// state all segments must carry current acknowledgment
		// information."
		drop, err := e.rcv.handleRcvdSegment(s)
		if err != nil {
			return false, err
		}
		if drop {
			return true, nil
		}

		// Now check if the received segment has caused us to transition
		// to a CLOSED state, if yes then terminate processing and do
		// not invoke the sender.
		state := e.EndpointState()
		if state == StateClose {
			// When we get into StateClose while processing from the queue,
			// return immediately and let the protocolMainloop handle it.
			//
			// We can reach StateClose only while processing a previous segment
			// or a notification from the protocolMainLoop (caller goroutine).
			// This means that with this return, the segment dequeue below can
			// never occur on a closed endpoint.
			return false, nil
		}

		e.snd.handleRcvdSegment(s)
	}

	return true, nil
}

// keepaliveTimerExpired is called when the keepaliveTimer fires. We send TCP
// keepalive packets periodically when the connection is idle. If we don't hear
// from the other side after a number of tries, we terminate the connection.
// +checklocks:e.mu
// +checklocksalias:e.snd.ep.mu=e.mu
func (e *endpoint) keepaliveTimerExpired() tcpip.Error {
	userTimeout := e.userTimeout

	e.keepalive.Lock()
	if !e.SocketOptions().GetKeepAlive() || e.keepalive.timer.isZero() || !e.keepalive.timer.checkExpiration() {
		e.keepalive.Unlock()
		return nil
	}

	// If a userTimeout is set then abort the connection if it is
	// exceeded.
	if userTimeout != 0 && e.stack.Clock().NowMonotonic().Sub(e.rcv.lastRcvdAckTime) >= userTimeout && e.keepalive.unacked > 0 {
		e.keepalive.Unlock()
		e.stack.Stats().TCP.EstablishedTimedout.Increment()
		return &tcpip.ErrTimeout{}
	}

	if e.keepalive.unacked >= e.keepalive.count {
		e.keepalive.Unlock()
		e.stack.Stats().TCP.EstablishedTimedout.Increment()
		return &tcpip.ErrTimeout{}
	}

	// RFC1122 4.2.3.6: TCP keepalive is a dataless ACK with
	// seg.seq = snd.nxt-1.
	e.keepalive.unacked++
	e.keepalive.Unlock()
	e.snd.sendEmptySegment(header.TCPFlagAck, e.snd.SndNxt-1)
	e.resetKeepaliveTimer(false)
	return nil
}

// resetKeepaliveTimer restarts or stops the keepalive timer, depending on
// whether it is enabled for this endpoint.
func (e *endpoint) resetKeepaliveTimer(receivedData bool) {
	e.keepalive.Lock()
	defer e.keepalive.Unlock()
	if e.keepalive.timer.isZero() {
		if state := e.EndpointState(); !state.closed() {
			panic(fmt.Sprintf("Unexpected state when the keepalive time is cleaned up, got %s, want %s or %s", state, StateClose, StateError))
		}
		return
	}
	if receivedData {
		e.keepalive.unacked = 0
	}
	// Start the keepalive timer IFF it's enabled and there is no pending
	// data to send.
	if !e.SocketOptions().GetKeepAlive() || e.snd == nil || e.snd.SndUna != e.snd.SndNxt {
		e.keepalive.timer.disable()
		return
	}
	if e.keepalive.unacked > 0 {
		e.keepalive.timer.enable(e.keepalive.interval)
	} else {
		e.keepalive.timer.enable(e.keepalive.idle)
	}
}

// disableKeepaliveTimer stops the keepalive timer.
func (e *endpoint) disableKeepaliveTimer() {
	e.keepalive.Lock()
	e.keepalive.timer.disable()
	e.keepalive.Unlock()
}

// finWait2TimerExpired is called when the FIN-WAIT-2 timeout is hit
// and the peer hasn't sent us a FIN.
func (e *endpoint) finWait2TimerExpired() {
	e.mu.Lock()
	e.transitionToStateCloseLocked()
	e.mu.Unlock()
	e.drainClosingSegmentQueue()
	e.waiterQueue.Notify(waiter.EventHUp | waiter.EventErr | waiter.ReadableEvents | waiter.WritableEvents)
}

// +checklocks:e.mu
func (e *endpoint) handshakeFailed(err tcpip.Error) {
	e.lastErrorMu.Lock()
	e.lastError = err
	e.lastErrorMu.Unlock()
	// handshakeFailed is also called from startHandshake when a listener
	// transitions out of Listen state by the time the SYN is processed. In
	// such cases the handshake is never initialized and the newly created
	// endpoint is closed right away.
	if e.h != nil && e.h.retransmitTimer != nil {
		e.h.retransmitTimer.stop()
	}
	e.hardError = err
	e.cleanupLocked()
	e.setEndpointState(StateError)
}

// handleTimeWaitSegments processes segments received during TIME_WAIT
// state.
// +checklocks:e.mu
// +checklocksalias:e.rcv.ep.mu=e.mu
func (e *endpoint) handleTimeWaitSegments() (extendTimeWait bool, reuseTW func()) {
	for i := 0; i < maxSegmentsPerWake; i++ {
		s := e.segmentQueue.dequeue()
		if s == nil {
			break
		}
		extTW, newSyn := e.rcv.handleTimeWaitSegment(s)
		if newSyn {
			info := e.TransportEndpointInfo
			newID := info.ID
			newID.RemoteAddress = ""
			newID.RemotePort = 0
			netProtos := []tcpip.NetworkProtocolNumber{info.NetProto}
			// If the local address is an IPv4 address then also
			// look for IPv6 dual stack endpoints that might be
			// listening on the local address.
			if newID.LocalAddress.To4() != "" {
				netProtos = []tcpip.NetworkProtocolNumber{header.IPv4ProtocolNumber, header.IPv6ProtocolNumber}
			}
			for _, netProto := range netProtos {
				if listenEP := e.stack.FindTransportEndpoint(netProto, info.TransProto, newID, s.pkt.NICID); listenEP != nil {
					tcpEP := listenEP.(*endpoint)
					if EndpointState(tcpEP.State()) == StateListen {
						reuseTW = func() {
							if !tcpEP.enqueueSegment(s) {
								return
							}
							tcpEP.notifyProcessor()
							s.DecRef()
						}
						// We explicitly do not DecRef the segment as it's still valid and
						// being reflected to a listening endpoint.
						return false, reuseTW
					}
				}
			}
		}
		if extTW {
			extendTimeWait = true
		}
		s.DecRef()
	}
	return extendTimeWait, nil
}

// +checklocks:e.mu
func (e *endpoint) getTimeWaitDuration() time.Duration {
	timeWaitDuration := DefaultTCPTimeWaitTimeout

	// Get the stack wide configuration.
	var tcpTW tcpip.TCPTimeWaitTimeoutOption
	if err := e.stack.TransportProtocolOption(ProtocolNumber, &tcpTW); err == nil {
		timeWaitDuration = time.Duration(tcpTW)
	}
	return timeWaitDuration
}

// timeWaitTimerExpired is called when an endpoint completes the required time
// (typically 2 * MSL unless configured to something else at a stack level) in
// TIME-WAIT state.
func (e *endpoint) timeWaitTimerExpired() {
	e.mu.Lock()
	if e.EndpointState() != StateTimeWait {
		e.mu.Unlock()
		return
	}
	e.transitionToStateCloseLocked()
	e.mu.Unlock()
	e.drainClosingSegmentQueue()
	e.waiterQueue.Notify(waiter.EventHUp | waiter.EventErr | waiter.ReadableEvents | waiter.WritableEvents)
}

// notifyProcessor queues this endpoint for processing to its TCP processor.
func (e *endpoint) notifyProcessor() {
	// We use TryLock here to avoid deadlocks in cases where a listening endpoint that is being
	// closed tries to abort half completed connections which in turn try to queue any segments
	// queued to that endpoint back to the same listening endpoint (because it may have got
	// segments that matched its id but were either a RST or a new SYN which must be handled
	// by a listening endpoint). In such cases the Close() on the listening endpoint will handle
	// any queued segments after it releases the lock.
	if !e.mu.TryLock() {
		return
	}
	processor := e.protocol.dispatcher.selectProcessor(e.ID)
	e.mu.Unlock()
	processor.queueEndpoint(e)
}
