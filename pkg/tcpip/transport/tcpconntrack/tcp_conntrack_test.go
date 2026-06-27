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

package tcpconntrack_test

import (
	"os"
	"testing"

	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcpconntrack"
)

// connected creates a connection tracker TCB and sets it to a connected state
// by performing a 3-way handshake.
func connected(t *testing.T, iss, irs uint32, isw, irw uint16) *tcpconntrack.TCB {
	// Send SYN.
	tcp := make(header.TCP, header.TCPMinimumSize)
	tcp.Encode(&header.TCPFields{
		SeqNum:     iss,
		AckNum:     0,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagSyn,
		WindowSize: irw,
	})

	tcb := tcpconntrack.TCB{}
	tcb.Init(tcp, dataLen(tcp))

	// Receive SYN-ACK.
	tcp.Encode(&header.TCPFields{
		SeqNum:     irs,
		AckNum:     iss + 1,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagSyn | header.TCPFlagAck,
		WindowSize: isw,
	})

	if r := tcb.UpdateStateReply(tcp, dataLen(tcp)); r != tcpconntrack.ResultAlive {
		t.Fatalf("Bad result: got %v, want %v", r, tcpconntrack.ResultAlive)
	}

	// Send ACK.
	tcp.Encode(&header.TCPFields{
		SeqNum:     iss + 1,
		AckNum:     irs + 1,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagAck,
		WindowSize: irw,
	})

	if r := tcb.UpdateStateOriginal(tcp, dataLen(tcp)); r != tcpconntrack.ResultAlive {
		t.Fatalf("Bad result: got %v, want %v", r, tcpconntrack.ResultAlive)
	}

	return &tcb
}

func TestConnectionRefused(t *testing.T) {
	// Send SYN.
	tcp := make(header.TCP, header.TCPMinimumSize)
	tcp.Encode(&header.TCPFields{
		SeqNum:     1234,
		AckNum:     0,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagSyn,
		WindowSize: 30000,
	})

	tcb := tcpconntrack.TCB{}
	tcb.Init(tcp, dataLen(tcp))

	// Receive RST.
	tcp.Encode(&header.TCPFields{
		SeqNum:     789,
		AckNum:     1235,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagRst | header.TCPFlagAck,
		WindowSize: 50000,
	})

	if r := tcb.UpdateStateReply(tcp, dataLen(tcp)); r != tcpconntrack.ResultReset {
		t.Fatalf("Bad result: got %v, want %v", r, tcpconntrack.ResultReset)
	}
}

func TestConnectionRefusedInSynRcvd(t *testing.T) {
	// Send SYN.
	tcp := make(header.TCP, header.TCPMinimumSize)
	tcp.Encode(&header.TCPFields{
		SeqNum:     1234,
		AckNum:     0,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagSyn,
		WindowSize: 30000,
	})

	tcb := tcpconntrack.TCB{}
	tcb.Init(tcp, dataLen(tcp))

	// Receive SYN.
	tcp.Encode(&header.TCPFields{
		SeqNum:     789,
		AckNum:     0,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagSyn,
		WindowSize: 50000,
	})

	if r := tcb.UpdateStateReply(tcp, dataLen(tcp)); r != tcpconntrack.ResultAlive {
		t.Fatalf("Bad result: got %v, want %v", r, tcpconntrack.ResultAlive)
	}

	// Receive RST with no ACK.
	tcp.Encode(&header.TCPFields{
		SeqNum:     790,
		AckNum:     0,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagRst,
		WindowSize: 50000,
	})

	if r := tcb.UpdateStateReply(tcp, dataLen(tcp)); r != tcpconntrack.ResultReset {
		t.Fatalf("Bad result: got %v, want %v", r, tcpconntrack.ResultReset)
	}
}

func TestConnectionResetInSynRcvd(t *testing.T) {
	// Send SYN.
	tcp := make(header.TCP, header.TCPMinimumSize)
	tcp.Encode(&header.TCPFields{
		SeqNum:     1234,
		AckNum:     0,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagSyn,
		WindowSize: 30000,
	})

	tcb := tcpconntrack.TCB{}
	tcb.Init(tcp, dataLen(tcp))

	// Receive SYN.
	tcp.Encode(&header.TCPFields{
		SeqNum:     789,
		AckNum:     0,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagSyn,
		WindowSize: 50000,
	})

	if r := tcb.UpdateStateReply(tcp, dataLen(tcp)); r != tcpconntrack.ResultAlive {
		t.Fatalf("Bad result: got %v, want %v", r, tcpconntrack.ResultAlive)
	}

	// Send RST with no ACK.
	tcp.Encode(&header.TCPFields{
		SeqNum:     1235,
		AckNum:     0,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagRst,
	})

	if r := tcb.UpdateStateOriginal(tcp, dataLen(tcp)); r != tcpconntrack.ResultReset {
		t.Fatalf("Bad result: got %v, want %v", r, tcpconntrack.ResultReset)
	}
}

func TestRetransmitOnSynSent(t *testing.T) {
	// Send initial SYN.
	tcp := make(header.TCP, header.TCPMinimumSize)
	tcp.Encode(&header.TCPFields{
		SeqNum:     1234,
		AckNum:     0,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagSyn,
		WindowSize: 30000,
	})

	tcb := tcpconntrack.TCB{}
	tcb.Init(tcp, dataLen(tcp))

	// Retransmit the same SYN.
	if r := tcb.UpdateStateOriginal(tcp, dataLen(tcp)); r != tcpconntrack.ResultConnecting {
		t.Fatalf("Bad result: got %v, want %v", r, tcpconntrack.ResultConnecting)
	}
}

func TestRetransmitOnSynRcvd(t *testing.T) {
	// Send initial SYN.
	tcp := make(header.TCP, header.TCPMinimumSize)
	tcp.Encode(&header.TCPFields{
		SeqNum:     1234,
		AckNum:     0,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagSyn,
		WindowSize: 30000,
	})

	tcb := tcpconntrack.TCB{}
	tcb.Init(tcp, dataLen(tcp))

	// Receive SYN. This will cause the state to go to SYN-RCVD.
	tcp.Encode(&header.TCPFields{
		SeqNum:     789,
		AckNum:     0,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagSyn,
		WindowSize: 50000,
	})

	if r := tcb.UpdateStateReply(tcp, dataLen(tcp)); r != tcpconntrack.ResultAlive {
		t.Fatalf("Bad result: got %v, want %v", r, tcpconntrack.ResultAlive)
	}

	// Retransmit the original SYN.
	tcp.Encode(&header.TCPFields{
		SeqNum:     1234,
		AckNum:     0,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagSyn,
		WindowSize: 30000,
	})

	if r := tcb.UpdateStateOriginal(tcp, dataLen(tcp)); r != tcpconntrack.ResultAlive {
		t.Fatalf("Bad result: got %v, want %v", r, tcpconntrack.ResultAlive)
	}

	// Transmit a SYN-ACK.
	tcp.Encode(&header.TCPFields{
		SeqNum:     1234,
		AckNum:     790,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagSyn | header.TCPFlagAck,
		WindowSize: 30000,
	})

	if r := tcb.UpdateStateOriginal(tcp, dataLen(tcp)); r != tcpconntrack.ResultAlive {
		t.Fatalf("Bad result: got %v, want %v", r, tcpconntrack.ResultAlive)
	}
}

func TestClosedByOriginator(t *testing.T) {
	tcb := connected(t, 1234, 789, 30000, 50000)

	// Send FIN.
	tcp := make(header.TCP, header.TCPMinimumSize)
	tcp.Encode(&header.TCPFields{
		SeqNum:     1235,
		AckNum:     790,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagAck | header.TCPFlagFin,
		WindowSize: 30000,
	})

	if r := tcb.UpdateStateOriginal(tcp, dataLen(tcp)); r != tcpconntrack.ResultAlive {
		t.Fatalf("Bad result: got %v, want %v", r, tcpconntrack.ResultAlive)
	}

	// Receive FIN/ACK.
	tcp.Encode(&header.TCPFields{
		SeqNum:     790,
		AckNum:     1236,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagAck | header.TCPFlagFin,
		WindowSize: 50000,
	})

	if r := tcb.UpdateStateReply(tcp, dataLen(tcp)); r != tcpconntrack.ResultAlive {
		t.Fatalf("Bad result: got %v, want %v", r, tcpconntrack.ResultAlive)
	}

	// Send ACK.
	tcp.Encode(&header.TCPFields{
		SeqNum:     1236,
		AckNum:     791,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagAck,
		WindowSize: 30000,
	})

	if r := tcb.UpdateStateOriginal(tcp, dataLen(tcp)); r != tcpconntrack.ResultClosedByOriginator {
		t.Fatalf("Bad result: got %v, want %v", r, tcpconntrack.ResultClosedByOriginator)
	}
}

func TestClosedByResponder(t *testing.T) {
	tcb := connected(t, 1234, 789, 30000, 50000)

	// Receive FIN.
	tcp := make(header.TCP, header.TCPMinimumSize)
	tcp.Encode(&header.TCPFields{
		SeqNum:     790,
		AckNum:     1235,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagAck | header.TCPFlagFin,
		WindowSize: 50000,
	})

	if r := tcb.UpdateStateReply(tcp, dataLen(tcp)); r != tcpconntrack.ResultAlive {
		t.Fatalf("Bad result: got %v, want %v", r, tcpconntrack.ResultAlive)
	}

	// Send FIN/ACK.
	tcp.Encode(&header.TCPFields{
		SeqNum:     1235,
		AckNum:     791,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagAck | header.TCPFlagFin,
		WindowSize: 30000,
	})

	if r := tcb.UpdateStateOriginal(tcp, dataLen(tcp)); r != tcpconntrack.ResultAlive {
		t.Fatalf("Bad result: got %v, want %v", r, tcpconntrack.ResultAlive)
	}

	// Receive ACK.
	tcp.Encode(&header.TCPFields{
		SeqNum:     791,
		AckNum:     1236,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagAck,
		WindowSize: 50000,
	})

	if r := tcb.UpdateStateReply(tcp, dataLen(tcp)); r != tcpconntrack.ResultClosedByResponder {
		t.Fatalf("Bad result: got %v, want %v", r, tcpconntrack.ResultClosedByResponder)
	}
}

func TestSendAndReceiveDataClosedByOriginator(t *testing.T) {
	sseq := uint32(1234)
	rseq := uint32(789)
	tcb := connected(t, sseq, rseq, 30000, 50000)
	sseq++
	rseq++

	// Send some data.
	tcp := make(header.TCP, header.TCPMinimumSize+1024)

	for i := uint32(0); i < 10; i++ {
		// Send some data.
		tcp.Encode(&header.TCPFields{
			SeqNum:     sseq,
			AckNum:     rseq,
			DataOffset: header.TCPMinimumSize,
			Flags:      header.TCPFlagAck,
			WindowSize: 30000,
		})
		sseq += uint32(dataLen(tcp)) - header.TCPMinimumSize

		if r := tcb.UpdateStateOriginal(tcp, dataLen(tcp)); r != tcpconntrack.ResultAlive {
			t.Fatalf("Bad result: got %v, want %v", r, tcpconntrack.ResultAlive)
		}

		// Receive ack for data.
		tcp.Encode(&header.TCPFields{
			SeqNum:     rseq,
			AckNum:     sseq,
			DataOffset: header.TCPMinimumSize,
			Flags:      header.TCPFlagAck,
			WindowSize: 50000,
		})

		if r := tcb.UpdateStateReply(tcp[:header.TCPMinimumSize], dataLen(tcp)); r != tcpconntrack.ResultAlive {
			t.Fatalf("Bad result: got %v, want %v", r, tcpconntrack.ResultAlive)
		}
	}

	for i := uint32(0); i < 10; i++ {
		// Receive some data.
		tcp.Encode(&header.TCPFields{
			SeqNum:     rseq,
			AckNum:     sseq,
			DataOffset: header.TCPMinimumSize,
			Flags:      header.TCPFlagAck,
			WindowSize: 50000,
		})
		rseq += uint32(dataLen(tcp))

		if r := tcb.UpdateStateReply(tcp, dataLen(tcp)); r != tcpconntrack.ResultAlive {
			t.Fatalf("Bad result: got %v, want %v", r, tcpconntrack.ResultAlive)
		}

		// Send ack for data.
		tcp.Encode(&header.TCPFields{
			SeqNum:     sseq,
			AckNum:     rseq,
			DataOffset: header.TCPMinimumSize,
			Flags:      header.TCPFlagAck,
			WindowSize: 30000,
		})

		if r := tcb.UpdateStateOriginal(tcp[:header.TCPMinimumSize], dataLen(tcp)); r != tcpconntrack.ResultAlive {
			t.Fatalf("Bad result: got %v, want %v", r, tcpconntrack.ResultAlive)
		}
	}

	// Send FIN.
	tcp = tcp[:header.TCPMinimumSize]
	tcp.Encode(&header.TCPFields{
		SeqNum:     sseq,
		AckNum:     rseq,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagAck | header.TCPFlagFin,
		WindowSize: 30000,
	})
	sseq++

	if r := tcb.UpdateStateOriginal(tcp, dataLen(tcp)); r != tcpconntrack.ResultAlive {
		t.Fatalf("Bad result: got %v, want %v", r, tcpconntrack.ResultAlive)
	}

	// Receive FIN/ACK.
	tcp.Encode(&header.TCPFields{
		SeqNum:     rseq,
		AckNum:     sseq,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagAck | header.TCPFlagFin,
		WindowSize: 50000,
	})
	rseq++

	if r := tcb.UpdateStateReply(tcp, dataLen(tcp)); r != tcpconntrack.ResultAlive {
		t.Fatalf("Bad result: got %v, want %v", r, tcpconntrack.ResultAlive)
	}

	// Send ACK.
	tcp.Encode(&header.TCPFields{
		SeqNum:     sseq,
		AckNum:     rseq,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagAck,
		WindowSize: 30000,
	})

	if r := tcb.UpdateStateOriginal(tcp, dataLen(tcp)); r != tcpconntrack.ResultClosedByOriginator {
		t.Fatalf("Bad result: got %v, want %v", r, tcpconntrack.ResultClosedByOriginator)
	}
}

func TestIgnoreBadResetOnSynSent(t *testing.T) {
	// Send SYN.
	tcp := make(header.TCP, header.TCPMinimumSize)
	tcp.Encode(&header.TCPFields{
		SeqNum:     1234,
		AckNum:     0,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagSyn,
		WindowSize: 30000,
	})

	tcb := tcpconntrack.TCB{}
	tcb.Init(tcp, dataLen(tcp))

	// Receive a RST with a bad ACK, it should not cause the connection to
	// be reset.
	acks := []uint32{1234, 1236, 1000, 5000}
	flags := []header.TCPFlags{header.TCPFlagRst, header.TCPFlagRst | header.TCPFlagAck}
	for _, a := range acks {
		for _, f := range flags {
			tcp.Encode(&header.TCPFields{
				SeqNum:     789,
				AckNum:     a,
				DataOffset: header.TCPMinimumSize,
				Flags:      f,
				WindowSize: 50000,
			})

			if r := tcb.UpdateStateReply(tcp, dataLen(tcp)); r != tcpconntrack.ResultConnecting {
				t.Fatalf("Bad result: got %v, want %v", r, tcpconntrack.ResultAlive)
			}
		}
	}

	// Complete the handshake.
	// Receive SYN-ACK.
	tcp.Encode(&header.TCPFields{
		SeqNum:     789,
		AckNum:     1235,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagSyn | header.TCPFlagAck,
		WindowSize: 50000,
	})

	if r := tcb.UpdateStateReply(tcp, dataLen(tcp)); r != tcpconntrack.ResultAlive {
		t.Fatalf("Bad result: got %v, want %v", r, tcpconntrack.ResultAlive)
	}

	// Send ACK.
	tcp.Encode(&header.TCPFields{
		SeqNum:     1235,
		AckNum:     790,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagAck,
		WindowSize: 30000,
	})

	if r := tcb.UpdateStateOriginal(tcp, dataLen(tcp)); r != tcpconntrack.ResultAlive {
		t.Fatalf("Bad result: got %v, want %v", r, tcpconntrack.ResultAlive)
	}
}

// dataLen returns the length of the TCP payload assuming that both the header
// and payload are in tcp.
func dataLen(tcp header.TCP) int {
	return len(tcp) - int(tcp.DataOffset())
}

func TestWindowScaling(t *testing.T) {
	// Send SYN with WS option (scale 2).
	opts := make([]byte, 4)
	header.EncodeWSOption(2, opts)
	header.EncodeNOP(opts[3:])

	tcp := make(header.TCP, header.TCPMinimumSize+len(opts))
	tcp.Encode(&header.TCPFields{
		SeqNum:     1234,
		AckNum:     0,
		DataOffset: header.TCPMinimumSize + uint8(len(opts)),
		Flags:      header.TCPFlagSyn,
		WindowSize: 10000,
	})
	copy(tcp[header.TCPMinimumSize:], opts)

	tcb := tcpconntrack.TCB{}
	tcb.Init(tcp, dataLen(tcp))

	// Receive SYN-ACK with WS option (scale 3).
	header.EncodeWSOption(3, opts)
	header.EncodeNOP(opts[3:])

	tcp.Encode(&header.TCPFields{
		SeqNum:     789,
		AckNum:     1235,
		DataOffset: header.TCPMinimumSize + uint8(len(opts)),
		Flags:      header.TCPFlagSyn | header.TCPFlagAck,
		WindowSize: 20000,
	})
	copy(tcp[header.TCPMinimumSize:], opts)

	if r := tcb.UpdateStateReply(tcp, dataLen(tcp)); r != tcpconntrack.ResultAlive {
		t.Fatalf("Bad result: got %v, want %v", r, tcpconntrack.ResultAlive)
	}

	// Send another packet from reply to update window with scaling.
	tcp = make(header.TCP, header.TCPMinimumSize)
	tcp.Encode(&header.TCPFields{
		SeqNum:     790,
		AckNum:     1235,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagAck,
		WindowSize: 20000,
	})
	if r := tcb.UpdateStateReply(tcp, dataLen(tcp)); r != tcpconntrack.ResultAlive {
		t.Fatalf("Bad result: got %v, want %v", r, tcpconntrack.ResultAlive)
	}

	// Now connection is established.
	// Original window size advertised by reply was 20000 << 3 = 160000.
	// So reply can accept sequence numbers up to 1235 + 160000 = 161235.

	// Send data from original with sequence number within that range.
	// Let's send a packet at seq 100000.
	tcp.Encode(&header.TCPFields{
		SeqNum:     100000,
		AckNum:     790,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagAck,
		WindowSize: 10000,
	})

	if r := tcb.UpdateStateOriginal(tcp, dataLen(tcp)); r != tcpconntrack.ResultAlive {
		t.Fatalf("Bad result: got %v, want %v", r, tcpconntrack.ResultAlive)
	}

	// Send FIN from original at seq 100000.
	tcp.Encode(&header.TCPFields{
		SeqNum:     100000,
		AckNum:     790,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagAck | header.TCPFlagFin,
		WindowSize: 10000,
	})
	if r := tcb.UpdateStateOriginal(tcp, dataLen(tcp)); r != tcpconntrack.ResultAlive {
		t.Fatalf("Bad result: got %v, want %v", r, tcpconntrack.ResultAlive)
	}

	// Receive ACK for FIN (ack 100001).
	tcp.Encode(&header.TCPFields{
		SeqNum:     790,
		AckNum:     100001,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagAck,
		WindowSize: 10000,
	})
	if r := tcb.UpdateStateReply(tcp, dataLen(tcp)); r != tcpconntrack.ResultAlive {
		t.Fatalf("Bad result: got %v, want %v", r, tcpconntrack.ResultAlive)
	}

	// Receive FIN from reply.
	tcp.Encode(&header.TCPFields{
		SeqNum:     790,
		AckNum:     100001,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagAck | header.TCPFlagFin,
		WindowSize: 10000,
	})
	if r := tcb.UpdateStateReply(tcp, dataLen(tcp)); r != tcpconntrack.ResultAlive {
		t.Fatalf("Bad result: got %v, want %v", r, tcpconntrack.ResultAlive)
	}

	// Send ACK from original.
	tcp.Encode(&header.TCPFields{
		SeqNum:     100001,
		AckNum:     791,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagAck,
		WindowSize: 10000,
	})
	if r := tcb.UpdateStateOriginal(tcp, dataLen(tcp)); r != tcpconntrack.ResultClosedByOriginator {
		t.Fatalf("Bad result: got %v, want %v", r, tcpconntrack.ResultClosedByOriginator)
	}
}

func TestWindowScalingDisabled(t *testing.T) {
	// Send SYN without WS option.
	tcp := make(header.TCP, header.TCPMinimumSize)
	tcp.Encode(&header.TCPFields{
		SeqNum:     1234,
		AckNum:     0,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagSyn,
		WindowSize: 10000,
	})

	tcb := tcpconntrack.TCB{}
	tcb.Init(tcp, dataLen(tcp))

	// Receive SYN-ACK without WS option.
	tcp.Encode(&header.TCPFields{
		SeqNum:     789,
		AckNum:     1235,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagSyn | header.TCPFlagAck,
		WindowSize: 20000,
	})

	if r := tcb.UpdateStateReply(tcp, dataLen(tcp)); r != tcpconntrack.ResultAlive {
		t.Fatalf("Bad result: got %v, want %v", r, tcpconntrack.ResultAlive)
	}

	// Send data from original with sequence number outside unscaled window.
	// Window is [1235, 1235 + 20000 = 21235).
	// Let's send a packet at seq 100000.
	tcp.Encode(&header.TCPFields{
		SeqNum:     100000,
		AckNum:     790,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagAck,
		WindowSize: 10000,
	})
	if r := tcb.UpdateStateOriginal(tcp, dataLen(tcp)); r != tcpconntrack.ResultAlive {
		t.Fatalf("Bad result: got %v, want %v", r, tcpconntrack.ResultAlive)
	}

	// Send FIN from original at seq 100000.
	tcp.Encode(&header.TCPFields{
		SeqNum:     100000,
		AckNum:     790,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagAck | header.TCPFlagFin,
		WindowSize: 10000,
	})
	if r := tcb.UpdateStateOriginal(tcp, dataLen(tcp)); r != tcpconntrack.ResultAlive {
		t.Fatalf("Bad result: got %v, want %v", r, tcpconntrack.ResultAlive)
	}

	// Receive ACK for FIN (ack 100001).
	tcp.Encode(&header.TCPFields{
		SeqNum:     790,
		AckNum:     100001,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagAck,
		WindowSize: 10000,
	})
	if r := tcb.UpdateStateReply(tcp, dataLen(tcp)); r != tcpconntrack.ResultAlive {
		t.Fatalf("Bad result: got %v, want %v", r, tcpconntrack.ResultAlive)
	}

	// Receive FIN from reply.
	tcp.Encode(&header.TCPFields{
		SeqNum:     790,
		AckNum:     100001,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagAck | header.TCPFlagFin,
		WindowSize: 10000,
	})
	if r := tcb.UpdateStateReply(tcp, dataLen(tcp)); r != tcpconntrack.ResultAlive {
		t.Fatalf("Bad result: got %v, want %v", r, tcpconntrack.ResultAlive)
	}

	// Send ACK from original.
	tcp.Encode(&header.TCPFields{
		SeqNum:     100001,
		AckNum:     791,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagAck,
		WindowSize: 10000,
	})
	// Should NOT be closed because the FIN was ignored!
	if r := tcb.UpdateStateOriginal(tcp, dataLen(tcp)); r != tcpconntrack.ResultAlive {
		t.Fatalf("Bad result: got %v, want %v", r, tcpconntrack.ResultAlive)
	}
}

func TestWindowScalingMaxShiftCapped(t *testing.T) {
	// Send SYN with WS option (scale 15).
	opts := make([]byte, 4)
	header.EncodeWSOption(15, opts)
	header.EncodeNOP(opts[3:])

	tcp := make(header.TCP, header.TCPMinimumSize+len(opts))
	tcp.Encode(&header.TCPFields{
		SeqNum:     1234,
		AckNum:     0,
		DataOffset: header.TCPMinimumSize + uint8(len(opts)),
		Flags:      header.TCPFlagSyn,
		WindowSize: 10000,
	})
	copy(tcp[header.TCPMinimumSize:], opts)

	tcb := tcpconntrack.TCB{}
	tcb.Init(tcp, dataLen(tcp))

	// Receive SYN-ACK with WS option (scale 15) and window 1000.
	// Both sides use 15, so both should cap at 14.
	header.EncodeWSOption(15, opts)
	header.EncodeNOP(opts[3:])

	tcp.Encode(&header.TCPFields{
		SeqNum:     789,
		AckNum:     1235,
		DataOffset: header.TCPMinimumSize + uint8(len(opts)),
		Flags:      header.TCPFlagSyn | header.TCPFlagAck,
		WindowSize: 1000,
	})
	copy(tcp[header.TCPMinimumSize:], opts)

	if r := tcb.UpdateStateReply(tcp, dataLen(tcp)); r != tcpconntrack.ResultAlive {
		t.Fatalf("Bad result: got %v, want %v", r, tcpconntrack.ResultAlive)
	}

	// Send another packet from reply to update window with scaling.
	// Window 1000. Effective window should be 1000 << 14 = 16384000.
	// If not capped (15), it would be 1000 << 15 = 32768000.
	tcp = make(header.TCP, header.TCPMinimumSize)
	tcp.Encode(&header.TCPFields{
		SeqNum:     790,
		AckNum:     1235,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagAck,
		WindowSize: 1000,
	})
	if r := tcb.UpdateStateReply(tcp, dataLen(tcp)); r != tcpconntrack.ResultAlive {
		t.Fatalf("Bad result: got %v, want %v", r, tcpconntrack.ResultAlive)
	}

	// Send data from original with seq 20,000,000 (out of capped window, in uncapped window).
	tcp.Encode(&header.TCPFields{
		SeqNum:     1235 + 20000000,
		AckNum:     790,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagAck,
		WindowSize: 10000,
	})

	// It should be IGNORED because it is out of window.
	if r := tcb.UpdateStateOriginal(tcp, dataLen(tcp)); r != tcpconntrack.ResultAlive {
		t.Fatalf("Bad result: got %v, want %v", r, tcpconntrack.ResultAlive)
	}

	// Verify it was ignored by trying to close connection with advanced seq.
	// If it was accepted, FIN at 1235 + 20000100 would be accepted.
	// If it was ignored, FIN at 1235 + 20000100 is out of window and ignored.
	tcp.Encode(&header.TCPFields{
		SeqNum:     1235 + 20000100,
		AckNum:     790,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagAck | header.TCPFlagFin,
		WindowSize: 10000,
	})
	tcb.UpdateStateOriginal(tcp, dataLen(tcp))

	// Receive FIN/ACK from reply.
	tcp.Encode(&header.TCPFields{
		SeqNum:     790,
		AckNum:     1235 + 20000101,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagAck | header.TCPFlagFin,
		WindowSize: 10000,
	})
	tcb.UpdateStateReply(tcp, dataLen(tcp))

	// Send ACK from original.
	tcp.Encode(&header.TCPFields{
		SeqNum:     1235 + 20000101,
		AckNum:     791,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagAck,
		WindowSize: 10000,
	})

	// Should NOT be closed because FIN was ignored!
	if r := tcb.UpdateStateOriginal(tcp, dataLen(tcp)); r != tcpconntrack.ResultAlive {
		t.Fatalf("Bad result: got %v, want %v", r, tcpconntrack.ResultAlive)
	}
}

func TestWindowScalingSynAckNotScaled(t *testing.T) {
	// Send SYN with WS option (scale 3).
	opts := make([]byte, 4)
	header.EncodeWSOption(3, opts)
	header.EncodeNOP(opts[3:])

	tcp := make(header.TCP, header.TCPMinimumSize+len(opts))
	tcp.Encode(&header.TCPFields{
		SeqNum:     1234,
		AckNum:     0,
		DataOffset: header.TCPMinimumSize + uint8(len(opts)),
		Flags:      header.TCPFlagSyn,
		WindowSize: 10000,
	})
	copy(tcp[header.TCPMinimumSize:], opts)

	tcb := tcpconntrack.TCB{}
	tcb.Init(tcp, dataLen(tcp))

	// Receive SYN-ACK with WS option (scale 3) and window 1000.
	header.EncodeWSOption(3, opts)
	header.EncodeNOP(opts[3:])

	tcp.Encode(&header.TCPFields{
		SeqNum:     789,
		AckNum:     1235,
		DataOffset: header.TCPMinimumSize + uint8(len(opts)),
		Flags:      header.TCPFlagSyn | header.TCPFlagAck,
		WindowSize: 1000,
	})
	copy(tcp[header.TCPMinimumSize:], opts)

	if r := tcb.UpdateStateReply(tcp, dataLen(tcp)); r != tcpconntrack.ResultAlive {
		t.Fatalf("Bad result: got %v, want %v", r, tcpconntrack.ResultAlive)
	}

	// Now connection is established.
	// Window in SYN-ACK should NOT be scaled. So window is 1000.
	// Data at 1235 + 500 should be ACCEPTED.
	tcp = make(header.TCP, header.TCPMinimumSize+100)
	tcp.Encode(&header.TCPFields{
		SeqNum:     1235 + 500,
		AckNum:     790,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagAck,
		WindowSize: 10000,
	})

	if r := tcb.UpdateStateOriginal(tcp, dataLen(tcp)); r != tcpconntrack.ResultAlive {
		t.Fatalf("Bad result: got %v, want %v", r, tcpconntrack.ResultAlive)
	}

	// Data at 1235 + 1500 should be IGNORED (out of window 1000).
	tcp.Encode(&header.TCPFields{
		SeqNum:     1235 + 1500,
		AckNum:     790,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagAck,
		WindowSize: 10000,
	})

	if r := tcb.UpdateStateOriginal(tcp, dataLen(tcp)); r != tcpconntrack.ResultAlive {
		t.Fatalf("Bad result: got %v, want %v", r, tcpconntrack.ResultAlive)
	}

	// Verify that 1235 + 1500 was ignored by sending ACK for it.
	// If it was accepted, ACK would be accepted.
	// If it was ignored, ACK is ahead of nxt and ignored.
	tcp = make(header.TCP, header.TCPMinimumSize)
	tcp.Encode(&header.TCPFields{
		SeqNum:     790,
		AckNum:     1235 + 1500,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagAck,
		WindowSize: 10000,
	})

	// Should not affect state.
	tcb.UpdateStateReply(tcp, dataLen(tcp))

	// Try to close connection using seq based on 1235 + 500 + 100 = 1235 + 600.
	// If 1235 + 1500 was ignored, this should work.
	tcp.Encode(&header.TCPFields{
		SeqNum:     1235 + 600,
		AckNum:     790,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagAck | header.TCPFlagFin,
		WindowSize: 10000,
	})
	tcb.UpdateStateOriginal(tcp, dataLen(tcp))

	// Receive FIN/ACK from reply.
	tcp.Encode(&header.TCPFields{
		SeqNum:     790,
		AckNum:     1235 + 601,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagAck | header.TCPFlagFin,
		WindowSize: 10000,
	})
	tcb.UpdateStateReply(tcp, dataLen(tcp))

	// Send ACK from original.
	tcp.Encode(&header.TCPFields{
		SeqNum:     1235 + 601,
		AckNum:     791,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagAck,
		WindowSize: 10000,
	})

	// Connection should CLOSE successfully!
	if r := tcb.UpdateStateOriginal(tcp, dataLen(tcp)); r != tcpconntrack.ResultClosedByOriginator {
		t.Fatalf("Bad result: got %v, want %v", r, tcpconntrack.ResultClosedByOriginator)
	}
}

func TestWindowScalingSynAckBoundary(t *testing.T) {
	// Send SYN with WS option (scale 3).
	opts := make([]byte, 4)
	header.EncodeWSOption(3, opts)
	header.EncodeNOP(opts[3:])

	tcp := make(header.TCP, header.TCPMinimumSize+len(opts))
	tcp.Encode(&header.TCPFields{
		SeqNum:     1234,
		AckNum:     0,
		DataOffset: header.TCPMinimumSize + uint8(len(opts)),
		Flags:      header.TCPFlagSyn,
		WindowSize: 10000,
	})
	copy(tcp[header.TCPMinimumSize:], opts)

	tcb := tcpconntrack.TCB{}
	tcb.Init(tcp, dataLen(tcp))

	// Receive SYN-ACK with WS option (scale 3) and window 1000.
	header.EncodeWSOption(3, opts)
	header.EncodeNOP(opts[3:])

	tcp.Encode(&header.TCPFields{
		SeqNum:     789,
		AckNum:     1235,
		DataOffset: header.TCPMinimumSize + uint8(len(opts)),
		Flags:      header.TCPFlagSyn | header.TCPFlagAck,
		WindowSize: 1000,
	})
	copy(tcp[header.TCPMinimumSize:], opts)

	if r := tcb.UpdateStateReply(tcp, dataLen(tcp)); r != tcpconntrack.ResultAlive {
		t.Fatalf("Bad result: got %v, want %v", r, tcpconntrack.ResultAlive)
	}

	// Now connection is established.
	// Window in SYN-ACK should NOT be scaled. So window is 1000.

	// Send data from original at boundary: 1235 + 1000 - 1 = 2234.
	// This should be ACCEPTED.
	tcp = make(header.TCP, header.TCPMinimumSize+1)
	tcp.Encode(&header.TCPFields{
		SeqNum:     2234,
		AckNum:     790,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagAck,
		WindowSize: 10000,
	})

	if r := tcb.UpdateStateOriginal(tcp, dataLen(tcp)); r != tcpconntrack.ResultAlive {
		t.Fatalf("Bad result: got %v, want %v", r, tcpconntrack.ResultAlive)
	}

	// Send data from original at boundary: 1235 + 1000 = 2235.
	// This should be IGNORED.
	tcp.Encode(&header.TCPFields{
		SeqNum:     2235,
		AckNum:     790,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagAck,
		WindowSize: 10000,
	})

	if r := tcb.UpdateStateOriginal(tcp, dataLen(tcp)); r != tcpconntrack.ResultAlive {
		t.Fatalf("Bad result: got %v, want %v", r, tcpconntrack.ResultAlive)
	}
}

func TestMain(m *testing.M) {
	refs.SetLeakMode(refs.LeaksPanic)
	code := m.Run()
	refs.DoLeakCheck()
	os.Exit(code)
}
