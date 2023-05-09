// Copyright 2021 The gVisor Authors.
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

package stack

import (
	"testing"

	"gvisor.dev/gvisor/pkg/bufferv2"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
	"gvisor.dev/gvisor/pkg/tcpip/testutil"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcpconntrack"
)

func TestReap(t *testing.T) {
	// Initialize conntrack.
	clock := faketime.NewManualClock()
	ct := ConnTrack{
		clock: clock,
	}
	ct.init()
	ct.checkNumTuples(t, 0)

	// We set rt.routeInfo.Loop to avoid a panic when handlePacket calls
	// rt.RequiresTXTransportChecksum.
	var rt Route
	rt.routeInfo.Loop = PacketLoop

	// Simulate sending a SYN. This will get the connection into conntrack, but
	// the connection won't be considered established. Thus the timeout for
	// reaping is unestablishedTimeout.
	pkt1 := genTCPPacket(genTCPOpts{})
	pkt1.tuple = ct.getConnAndUpdate(pkt1, true /* skipChecksumValidation */)
	if pkt1.tuple.conn.handlePacket(pkt1, Output, &rt) {
		t.Fatal("handlePacket() shouldn't perform any NAT")
	}
	ct.checkNumTuples(t, 1)

	// Travel a little into the future and send the same SYN. This should update
	// lastUsed, but per #6748 didn't.
	clock.Advance(unestablishedTimeout / 2)
	pkt2 := genTCPPacket(genTCPOpts{})
	pkt2.tuple = ct.getConnAndUpdate(pkt2, true /* skipChecksumValidation */)
	if pkt2.tuple.conn.handlePacket(pkt2, Output, &rt) {
		t.Fatal("handlePacket() shouldn't perform any NAT")
	}
	ct.checkNumTuples(t, 1)

	// Travel farther into the future - enough that failing to update lastUsed
	// would cause a reaping - and reap the whole table. Make sure the connection
	// hasn't been reaped.
	clock.Advance(unestablishedTimeout * 3 / 4)
	ct.reapEverything()
	ct.checkNumTuples(t, 1)

	// Travel past unestablishedTimeout to confirm the tuple is gone.
	clock.Advance(unestablishedTimeout / 2)
	ct.reapEverything()
	ct.checkNumTuples(t, 0)
}

func TestWindowScaling(t *testing.T) {
	tcs := []struct {
		name        string
		windowSize  uint16
		synScale    uint8
		synAckScale uint8
		dataLen     int
		finalSeq    uint32
	}{
		{
			name:       "no scale, full overlap",
			windowSize: 4,
			dataLen:    2,
			finalSeq:   2,
		},
		{
			name:       "no scale, partial overlap",
			windowSize: 4,
			dataLen:    8,
			finalSeq:   4,
		},
		{
			name:        "scale, full overlap",
			windowSize:  4,
			synScale:    1,
			synAckScale: 1,
			dataLen:     6,
			finalSeq:    6,
		},
		{
			name:        "scale, partial overlap",
			windowSize:  4,
			synScale:    1,
			synAckScale: 1,
			dataLen:     10,
			finalSeq:    8,
		},
		{
			name:        "SYN scale larger",
			windowSize:  4,
			synScale:    2,
			synAckScale: 1,
			dataLen:     10,
			finalSeq:    8,
		},
		{
			name:        "SYN/ACK scale larger",
			windowSize:  4,
			synScale:    1,
			synAckScale: 2,
			dataLen:     10,
			finalSeq:    10,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			testWindowScaling(t, tc.windowSize, tc.synScale, tc.synAckScale, tc.dataLen, tc.finalSeq)
		})
	}
}

// testWindowScaling performs a TCP handshake with the given parameters,
// attaching dataLen bytes as the payload to the final ACK.
func testWindowScaling(t *testing.T, windowSize uint16, synScale, synAckScale uint8, dataLen int, finalSeq uint32) {
	// Initialize conntrack.
	clock := faketime.NewManualClock()
	ct := ConnTrack{
		clock: clock,
	}
	ct.init()
	ct.checkNumTuples(t, 0)

	// We set rt.routeInfo.Loop to avoid a panic when handlePacket calls
	// rt.RequiresTXTransportChecksum.
	var rt Route
	rt.routeInfo.Loop = PacketLoop

	var (
		rwnd           = windowSize
		seqOrig        = uint32(10)
		seqRepl        = uint32(20)
		flags          = header.TCPFlags(header.TCPFlagSyn)
		originatorAddr = testutil.MustParse4("1.0.0.1")
		responderAddr  = testutil.MustParse4("1.0.0.2")
		originatorPort = uint16(5555)
		responderPort  = uint16(6666)
	)

	// Send SYN outbound through conntrack, simulating the Output hook.
	synPkt := genTCPPacket(genTCPOpts{
		windowSize:  &rwnd,
		windowScale: synScale,
		seqNum:      &seqOrig,
		flags:       &flags,
		srcAddr:     &originatorAddr,
		dstAddr:     &responderAddr,
		srcPort:     &originatorPort,
		dstPort:     &responderPort,
	})
	synPkt.tuple = ct.getConnAndUpdate(synPkt, true /* skipChecksumValidation */)
	if synPkt.tuple.conn.handlePacket(synPkt, Output, &rt) {
		t.Fatal("handlePacket() shouldn't perform any NAT")
	}
	ct.checkNumTuples(t, 1)

	// Simulate the Postrouting hook.
	synPkt.tuple.conn.finalize()
	conn := synPkt.tuple.conn
	synPkt.tuple = nil
	ct.checkNumTuples(t, 2)
	conn.stateMu.Lock()
	if got, want := conn.tcb.State(), tcpconntrack.ResultConnecting; got != want {
		t.Fatalf("connection in state %v, but wanted %v", got, want)
	}
	conn.stateMu.Unlock()
	conn.checkOriginalSeq(t, seqOrig+1)

	// Send SYN/ACK, simulating the Prerouting hook.
	seqOrig++
	flags |= header.TCPFlagAck
	synAckPkt := genTCPPacket(genTCPOpts{
		windowSize:  &windowSize,
		windowScale: synAckScale,
		seqNum:      &seqRepl,
		ackNum:      &seqOrig,
		flags:       &flags,
		srcAddr:     &responderAddr,
		dstAddr:     &originatorAddr,
		srcPort:     &responderPort,
		dstPort:     &originatorPort,
	})
	synAckPkt.tuple = ct.getConnAndUpdate(synAckPkt, true /* skipChecksumValidation */)
	if synAckPkt.tuple.conn.handlePacket(synAckPkt, Prerouting, &rt) {
		t.Fatal("handlePacket() shouldn't perform any NAT")
	}
	ct.checkNumTuples(t, 2)

	// Simulate the Input hook.
	synAckPkt.tuple.conn.finalize()
	synAckPkt.tuple = nil
	ct.checkNumTuples(t, 2)
	conn.stateMu.Lock()
	if got, want := conn.tcb.State(), tcpconntrack.ResultAlive; got != want {
		t.Fatalf("connection in state %v, but wanted %v", got, want)
	}
	conn.stateMu.Unlock()
	conn.checkReplySeq(t, seqRepl+1)

	// Send ACK with a payload, simulating the Output hook.
	seqRepl++
	flags = header.TCPFlagAck
	ackPkt := genTCPPacket(genTCPOpts{
		windowSize: &windowSize,
		seqNum:     &seqOrig,
		ackNum:     &seqRepl,
		flags:      &flags,
		data:       make([]byte, dataLen),
		srcAddr:    &originatorAddr,
		dstAddr:    &responderAddr,
		srcPort:    &originatorPort,
		dstPort:    &responderPort,
	})
	ackPkt.tuple = ct.getConnAndUpdate(ackPkt, true /* skipChecksumValidation */)
	if ackPkt.tuple.conn.handlePacket(ackPkt, Output, &rt) {
		t.Fatal("handlePacket() shouldn't perform any NAT")
	}
	ct.checkNumTuples(t, 2)

	// Simulate the Postrouting hook.
	ackPkt.tuple.conn.finalize()
	ackPkt.tuple = nil
	ct.checkNumTuples(t, 2)
	conn.stateMu.Lock()
	if got, want := conn.tcb.State(), tcpconntrack.ResultAlive; got != want {
		t.Fatalf("connection in state %v, but wanted %v", got, want)
	}
	conn.stateMu.Unlock()
	// Depending on the test, all or a fraction of dataLen will go towards
	// advancing the sequence number.
	conn.checkOriginalSeq(t, finalSeq+seqOrig)

	// Go into the future to make sure we don't reap active connections quickly.
	clock.Advance(unestablishedTimeout * 2)
	ct.reapEverything()
	ct.checkNumTuples(t, 2)

	// Go way into the future to make sure we eventually reap active connections.
	clock.Advance(establishedTimeout)
	ct.reapEverything()
	ct.checkNumTuples(t, 0)
}

type genTCPOpts struct {
	windowSize  *uint16
	windowScale uint8
	seqNum      *uint32
	ackNum      *uint32
	flags       *header.TCPFlags
	data        []byte
	srcAddr     *tcpip.Address
	dstAddr     *tcpip.Address
	srcPort     *uint16
	dstPort     *uint16
}

// genTCPPacket returns an initialized IPv4 TCP packet.
func genTCPPacket(opts genTCPOpts) PacketBufferPtr {
	// Get values from opts.
	windowSize := uint16(50000)
	if opts.windowSize != nil {
		windowSize = *opts.windowSize
	}
	tcpHdrSize := uint8(header.TCPMinimumSize)
	if opts.windowScale != 0 {
		tcpHdrSize += 4 // 3 bytes of window scale plus 1 of padding.
	}
	seqNum := uint32(7777)
	if opts.seqNum != nil {
		seqNum = *opts.seqNum
	}
	ackNum := uint32(8888)
	if opts.ackNum != nil {
		ackNum = *opts.ackNum
	}
	flags := header.TCPFlagSyn
	if opts.flags != nil {
		flags = *opts.flags
	}
	srcAddr := testutil.MustParse4("1.0.0.1")
	if opts.srcAddr != nil {
		srcAddr = *opts.srcAddr
	}
	dstAddr := testutil.MustParse4("1.0.0.2")
	if opts.dstAddr != nil {
		dstAddr = *opts.dstAddr
	}
	srcPort := uint16(5555)
	if opts.srcPort != nil {
		srcPort = *opts.srcPort
	}
	dstPort := uint16(6666)
	if opts.dstPort != nil {
		dstPort = *opts.dstPort
	}

	// Initialize the PacketBuffer.
	packetLen := header.IPv4MinimumSize + uint16(tcpHdrSize)
	pkt := NewPacketBuffer(PacketBufferOptions{
		ReserveHeaderBytes: int(packetLen),
		Payload:            bufferv2.MakeWithData(opts.data),
	})
	pkt.NetworkProtocolNumber = header.IPv4ProtocolNumber
	pkt.TransportProtocolNumber = header.TCPProtocolNumber

	// Craft the TCP header, including the window scale option if necessary.
	tcpHdr := header.TCP(pkt.TransportHeader().Push(int(tcpHdrSize)))
	tcpHdr[:header.TCPMinimumSize].Encode(&header.TCPFields{
		SrcPort:    srcPort,
		DstPort:    dstPort,
		SeqNum:     seqNum,
		AckNum:     ackNum,
		DataOffset: tcpHdrSize,
		Flags:      flags,
		WindowSize: windowSize,
		Checksum:   0, // Conntrack doesn't verify the checksum.
	})
	if opts.windowScale != 0 {
		// Set the window scale option, which is 3 bytes long. The option is
		// properly padded because the final remaining byte is already zeroed.
		_ = header.EncodeWSOption(int(opts.windowScale), tcpHdr[header.TCPMinimumSize:])
	}

	// Craft an IPv4 header.
	ipHdr := header.IPv4(pkt.NetworkHeader().Push(header.IPv4MinimumSize))
	ipHdr.Encode(&header.IPv4Fields{
		TotalLength: packetLen,
		Protocol:    uint8(header.TCPProtocolNumber),
		SrcAddr:     srcAddr,
		DstAddr:     dstAddr,
		Checksum:    0, // Conntrack doesn't verify the checksum.
	})

	return pkt
}

// checkNumTuples checks that there are exactly want tuples tracked by
// conntrack.
func (ct *ConnTrack) checkNumTuples(t *testing.T, want int) {
	t.Helper()
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	var total int
	for idx := range ct.buckets {
		ct.buckets[idx].mu.RLock()
		total += ct.buckets[idx].tuples.Len()
		ct.buckets[idx].mu.RUnlock()
	}

	if total != want {
		t.Fatalf("checkNumTuples: got %d, wanted %d", total, want)
	}
}

func (ct *ConnTrack) reapEverything() {
	var bucket int
	for {
		newBucket, _ := ct.reapUnused(bucket, 0 /* ignored */)
		// We started reaping at bucket 0. If the next bucket isn't after our
		// current bucket, we've gone through them all.
		if newBucket <= bucket {
			break
		}
		bucket = newBucket
	}
}

func (cn *conn) checkOriginalSeq(t *testing.T, seq uint32) {
	t.Helper()
	cn.stateMu.Lock()
	defer cn.stateMu.Unlock()

	if got, want := cn.tcb.OriginalSendSequenceNumber(), seqnum.Value(seq); got != want {
		t.Fatalf("checkOriginalSeq: got %d, wanted %d", got, want)
	}
}

func (cn *conn) checkReplySeq(t *testing.T, seq uint32) {
	t.Helper()
	cn.stateMu.Lock()
	defer cn.stateMu.Unlock()

	if got, want := cn.tcb.ReplySendSequenceNumber(), seqnum.Value(seq); got != want {
		t.Fatalf("checkReplySeq: got %d, wanted %d", got, want)
	}
}
