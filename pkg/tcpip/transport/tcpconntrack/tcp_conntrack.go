// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package tcpconntrack implements a TCP connection tracking object. It allows
// users with access to a segment stream to figure out when a connection is
// established, reset, and closed (and in the last case, who closed first).
package tcpconntrack

import (
	"gvisor.googlesource.com/gvisor/pkg/tcpip/header"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/seqnum"
)

// Result is returned when the state of a TCB is updated in response to an
// inbound or outbound segment.
type Result int

const (
	// ResultDrop indicates that the segment should be dropped.
	ResultDrop Result = iota

	// ResultConnecting indicates that the connection remains in a
	// connecting state.
	ResultConnecting

	// ResultAlive indicates that the connection remains alive (connected).
	ResultAlive

	// ResultReset indicates that the connection was reset.
	ResultReset

	// ResultClosedByPeer indicates that the connection was gracefully
	// closed, and the inbound stream was closed first.
	ResultClosedByPeer

	// ResultClosedBySelf indicates that the connection was gracefully
	// closed, and the outbound stream was closed first.
	ResultClosedBySelf
)

// TCB is a TCP Control Block. It holds state necessary to keep track of a TCP
// connection and inform the caller when the connection has been closed.
type TCB struct {
	inbound  stream
	outbound stream

	// State handlers.
	handlerInbound  func(*TCB, header.TCP) Result
	handlerOutbound func(*TCB, header.TCP) Result

	// firstFin holds a pointer to the first stream to send a FIN.
	firstFin *stream

	// state is the current state of the stream.
	state Result
}

// Init initializes the state of the TCB according to the initial SYN.
func (t *TCB) Init(initialSyn header.TCP) {
	t.handlerInbound = synSentStateInbound
	t.handlerOutbound = synSentStateOutbound

	iss := seqnum.Value(initialSyn.SequenceNumber())
	t.outbound.una = iss
	t.outbound.nxt = iss.Add(logicalLen(initialSyn))
	t.outbound.end = t.outbound.nxt

	// Even though "end" is a sequence number, we don't know the initial
	// receive sequence number yet, so we store the window size until we get
	// a SYN from the peer.
	t.inbound.una = 0
	t.inbound.nxt = 0
	t.inbound.end = seqnum.Value(initialSyn.WindowSize())
	t.state = ResultConnecting
}

// UpdateStateInbound updates the state of the TCB based on the supplied inbound
// segment.
func (t *TCB) UpdateStateInbound(tcp header.TCP) Result {
	st := t.handlerInbound(t, tcp)
	if st != ResultDrop {
		t.state = st
	}
	return st
}

// UpdateStateOutbound updates the state of the TCB based on the supplied
// outbound segment.
func (t *TCB) UpdateStateOutbound(tcp header.TCP) Result {
	st := t.handlerOutbound(t, tcp)
	if st != ResultDrop {
		t.state = st
	}
	return st
}

// IsAlive returns true as long as the connection is established(Alive)
// or connecting state.
func (t *TCB) IsAlive() bool {
	return !t.inbound.rstSeen && !t.outbound.rstSeen && (!t.inbound.closed() || !t.outbound.closed())
}

// OutboundSendSequenceNumber returns the snd.NXT for the outbound stream.
func (t *TCB) OutboundSendSequenceNumber() seqnum.Value {
	return t.outbound.nxt
}

// adapResult modifies the supplied "Result" according to the state of the TCB;
// if r is anything other than "Alive", or if one of the streams isn't closed
// yet, it is returned unmodified. Otherwise it's converted to either
// ClosedBySelf or ClosedByPeer depending on which stream was closed first.
func (t *TCB) adaptResult(r Result) Result {
	// Check the unmodified case.
	if r != ResultAlive || !t.inbound.closed() || !t.outbound.closed() {
		return r
	}

	// Find out which was closed first.
	if t.firstFin == &t.outbound {
		return ResultClosedBySelf
	}

	return ResultClosedByPeer
}

// synSentStateInbound is the state handler for inbound segments when the
// connection is in SYN-SENT state.
func synSentStateInbound(t *TCB, tcp header.TCP) Result {
	flags := tcp.Flags()
	ackPresent := flags&header.TCPFlagAck != 0
	ack := seqnum.Value(tcp.AckNumber())

	// Ignore segment if ack is present but not acceptable.
	if ackPresent && !(ack-1).InRange(t.outbound.una, t.outbound.nxt) {
		return ResultConnecting
	}

	// If reset is specified, we will let the packet through no matter what
	// but we will also destroy the connection if the ACK is present (and
	// implicitly acceptable).
	if flags&header.TCPFlagRst != 0 {
		if ackPresent {
			t.inbound.rstSeen = true
			return ResultReset
		}
		return ResultConnecting
	}

	// Ignore segment if SYN is not set.
	if flags&header.TCPFlagSyn == 0 {
		return ResultConnecting
	}

	// Update state informed by this SYN.
	irs := seqnum.Value(tcp.SequenceNumber())
	t.inbound.una = irs
	t.inbound.nxt = irs.Add(logicalLen(tcp))
	t.inbound.end += irs

	t.outbound.end = t.outbound.una.Add(seqnum.Size(tcp.WindowSize()))

	// If the ACK was set (it is acceptable), update our unacknowledgement
	// tracking.
	if ackPresent {
		// Advance the "una" and "end" indices of the outbound stream.
		if t.outbound.una.LessThan(ack) {
			t.outbound.una = ack
		}

		if end := ack.Add(seqnum.Size(tcp.WindowSize())); t.outbound.end.LessThan(end) {
			t.outbound.end = end
		}
	}

	// Update handlers so that new calls will be handled by new state.
	t.handlerInbound = allOtherInbound
	t.handlerOutbound = allOtherOutbound

	return ResultAlive
}

// synSentStateOutbound is the state handler for outbound segments when the
// connection is in SYN-SENT state.
func synSentStateOutbound(t *TCB, tcp header.TCP) Result {
	// Drop outbound segments that aren't retransmits of the original one.
	if tcp.Flags() != header.TCPFlagSyn ||
		tcp.SequenceNumber() != uint32(t.outbound.una) {
		return ResultDrop
	}

	// Update the receive window. We only remember the largest value seen.
	if wnd := seqnum.Value(tcp.WindowSize()); wnd > t.inbound.end {
		t.inbound.end = wnd
	}

	return ResultConnecting
}

// update updates the state of inbound and outbound streams, given the supplied
// inbound segment. For outbound segments, this same function can be called with
// swapped inbound/outbound streams.
func update(tcp header.TCP, inbound, outbound *stream, firstFin **stream) Result {
	// Ignore segments out of the window.
	s := seqnum.Value(tcp.SequenceNumber())
	if !inbound.acceptable(s, dataLen(tcp)) {
		return ResultAlive
	}

	flags := tcp.Flags()
	if flags&header.TCPFlagRst != 0 {
		inbound.rstSeen = true
		return ResultReset
	}

	// Ignore segments that don't have the ACK flag, and those with the SYN
	// flag.
	if flags&header.TCPFlagAck == 0 || flags&header.TCPFlagSyn != 0 {
		return ResultAlive
	}

	// Ignore segments that acknowledge not yet sent data.
	ack := seqnum.Value(tcp.AckNumber())
	if outbound.nxt.LessThan(ack) {
		return ResultAlive
	}

	// Advance the "una" and "end" indices of the outbound stream.
	if outbound.una.LessThan(ack) {
		outbound.una = ack
	}

	if end := ack.Add(seqnum.Size(tcp.WindowSize())); outbound.end.LessThan(end) {
		outbound.end = end
	}

	// Advance the "nxt" index of the inbound stream.
	end := s.Add(logicalLen(tcp))
	if inbound.nxt.LessThan(end) {
		inbound.nxt = end
	}

	// Note the index of the FIN segment. And stash away a pointer to the
	// first stream to see a FIN.
	if flags&header.TCPFlagFin != 0 && !inbound.finSeen {
		inbound.finSeen = true
		inbound.fin = end - 1

		if *firstFin == nil {
			*firstFin = inbound
		}
	}

	return ResultAlive
}

// allOtherInbound is the state handler for inbound segments in all states
// except SYN-SENT.
func allOtherInbound(t *TCB, tcp header.TCP) Result {
	return t.adaptResult(update(tcp, &t.inbound, &t.outbound, &t.firstFin))
}

// allOtherOutbound is the state handler for outbound segments in all states
// except SYN-SENT.
func allOtherOutbound(t *TCB, tcp header.TCP) Result {
	return t.adaptResult(update(tcp, &t.outbound, &t.inbound, &t.firstFin))
}

// streams holds the state of a TCP unidirectional stream.
type stream struct {
	// The interval [una, end) is the allowed interval as defined by the
	// receiver, i.e., anything less than una has already been acknowledged
	// and anything greater than or equal to end is beyond the receiver
	// window. The interval [una, nxt) is the acknowledgable range, whose
	// right edge indicates the sequence number of the next byte to be sent
	// by the sender, i.e., anything greater than or equal to nxt hasn't
	// been sent yet.
	una seqnum.Value
	nxt seqnum.Value
	end seqnum.Value

	// finSeen indicates if a FIN has already been sent on this stream.
	finSeen bool

	// fin is the sequence number of the FIN. It is only valid after finSeen
	// is set to true.
	fin seqnum.Value

	// rstSeen indicates if a RST has already been sent on this stream.
	rstSeen bool
}

// acceptable determines if the segment with the given sequence number and data
// length is acceptable, i.e., if it's within the [una, end) window or, in case
// the window is zero, if it's a packet with no payload and sequence number
// equal to una.
func (s *stream) acceptable(segSeq seqnum.Value, segLen seqnum.Size) bool {
	wnd := s.una.Size(s.end)
	if wnd == 0 {
		return segLen == 0 && segSeq == s.una
	}

	// Make sure [segSeq, seqSeq+segLen) is non-empty.
	if segLen == 0 {
		segLen = 1
	}

	return seqnum.Overlap(s.una, wnd, segSeq, segLen)
}

// closed determines if the stream has already been closed. This happens when
// a FIN has been set by the sender and acknowledged by the receiver.
func (s *stream) closed() bool {
	return s.finSeen && s.fin.LessThan(s.una)
}

// dataLen returns the length of the TCP segment payload.
func dataLen(tcp header.TCP) seqnum.Size {
	return seqnum.Size(len(tcp) - int(tcp.DataOffset()))
}

// logicalLen calculates the logical length of the TCP segment.
func logicalLen(tcp header.TCP) seqnum.Size {
	l := dataLen(tcp)
	flags := tcp.Flags()
	if flags&header.TCPFlagSyn != 0 {
		l++
	}
	if flags&header.TCPFlagFin != 0 {
		l++
	}
	return l
}
