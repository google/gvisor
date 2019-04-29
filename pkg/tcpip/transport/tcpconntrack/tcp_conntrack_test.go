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
	"testing"

	"gvisor.googlesource.com/gvisor/pkg/tcpip/header"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/transport/tcpconntrack"
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
	tcb.Init(tcp)

	// Receive SYN-ACK.
	tcp.Encode(&header.TCPFields{
		SeqNum:     irs,
		AckNum:     iss + 1,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagSyn | header.TCPFlagAck,
		WindowSize: isw,
	})

	if r := tcb.UpdateStateInbound(tcp); r != tcpconntrack.ResultAlive {
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

	if r := tcb.UpdateStateOutbound(tcp); r != tcpconntrack.ResultAlive {
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
	tcb.Init(tcp)

	// Receive RST.
	tcp.Encode(&header.TCPFields{
		SeqNum:     789,
		AckNum:     1235,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagRst | header.TCPFlagAck,
		WindowSize: 50000,
	})

	if r := tcb.UpdateStateInbound(tcp); r != tcpconntrack.ResultReset {
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
	tcb.Init(tcp)

	// Receive SYN.
	tcp.Encode(&header.TCPFields{
		SeqNum:     789,
		AckNum:     0,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagSyn,
		WindowSize: 50000,
	})

	if r := tcb.UpdateStateInbound(tcp); r != tcpconntrack.ResultAlive {
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

	if r := tcb.UpdateStateInbound(tcp); r != tcpconntrack.ResultReset {
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
	tcb.Init(tcp)

	// Receive SYN.
	tcp.Encode(&header.TCPFields{
		SeqNum:     789,
		AckNum:     0,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagSyn,
		WindowSize: 50000,
	})

	if r := tcb.UpdateStateInbound(tcp); r != tcpconntrack.ResultAlive {
		t.Fatalf("Bad result: got %v, want %v", r, tcpconntrack.ResultAlive)
	}

	// Send RST with no ACK.
	tcp.Encode(&header.TCPFields{
		SeqNum:     1235,
		AckNum:     0,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagRst,
	})

	if r := tcb.UpdateStateOutbound(tcp); r != tcpconntrack.ResultReset {
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
	tcb.Init(tcp)

	// Retransmit the same SYN.
	if r := tcb.UpdateStateOutbound(tcp); r != tcpconntrack.ResultConnecting {
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
	tcb.Init(tcp)

	// Receive SYN. This will cause the state to go to SYN-RCVD.
	tcp.Encode(&header.TCPFields{
		SeqNum:     789,
		AckNum:     0,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagSyn,
		WindowSize: 50000,
	})

	if r := tcb.UpdateStateInbound(tcp); r != tcpconntrack.ResultAlive {
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

	if r := tcb.UpdateStateOutbound(tcp); r != tcpconntrack.ResultAlive {
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

	if r := tcb.UpdateStateOutbound(tcp); r != tcpconntrack.ResultAlive {
		t.Fatalf("Bad result: got %v, want %v", r, tcpconntrack.ResultAlive)
	}
}

func TestClosedBySelf(t *testing.T) {
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

	if r := tcb.UpdateStateOutbound(tcp); r != tcpconntrack.ResultAlive {
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

	if r := tcb.UpdateStateInbound(tcp); r != tcpconntrack.ResultAlive {
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

	if r := tcb.UpdateStateOutbound(tcp); r != tcpconntrack.ResultClosedBySelf {
		t.Fatalf("Bad result: got %v, want %v", r, tcpconntrack.ResultClosedBySelf)
	}
}

func TestClosedByPeer(t *testing.T) {
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

	if r := tcb.UpdateStateInbound(tcp); r != tcpconntrack.ResultAlive {
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

	if r := tcb.UpdateStateOutbound(tcp); r != tcpconntrack.ResultAlive {
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

	if r := tcb.UpdateStateInbound(tcp); r != tcpconntrack.ResultClosedByPeer {
		t.Fatalf("Bad result: got %v, want %v", r, tcpconntrack.ResultClosedByPeer)
	}
}

func TestSendAndReceiveDataClosedBySelf(t *testing.T) {
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
		sseq += uint32(len(tcp)) - header.TCPMinimumSize

		if r := tcb.UpdateStateOutbound(tcp); r != tcpconntrack.ResultAlive {
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

		if r := tcb.UpdateStateInbound(tcp[:header.TCPMinimumSize]); r != tcpconntrack.ResultAlive {
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
		rseq += uint32(len(tcp)) - header.TCPMinimumSize

		if r := tcb.UpdateStateInbound(tcp); r != tcpconntrack.ResultAlive {
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

		if r := tcb.UpdateStateOutbound(tcp[:header.TCPMinimumSize]); r != tcpconntrack.ResultAlive {
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

	if r := tcb.UpdateStateOutbound(tcp); r != tcpconntrack.ResultAlive {
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

	if r := tcb.UpdateStateInbound(tcp); r != tcpconntrack.ResultAlive {
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

	if r := tcb.UpdateStateOutbound(tcp); r != tcpconntrack.ResultClosedBySelf {
		t.Fatalf("Bad result: got %v, want %v", r, tcpconntrack.ResultClosedBySelf)
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
	tcb.Init(tcp)

	// Receive a RST with a bad ACK, it should not cause the connection to
	// be reset.
	acks := []uint32{1234, 1236, 1000, 5000}
	flags := []uint8{header.TCPFlagRst, header.TCPFlagRst | header.TCPFlagAck}
	for _, a := range acks {
		for _, f := range flags {
			tcp.Encode(&header.TCPFields{
				SeqNum:     789,
				AckNum:     a,
				DataOffset: header.TCPMinimumSize,
				Flags:      f,
				WindowSize: 50000,
			})

			if r := tcb.UpdateStateInbound(tcp); r != tcpconntrack.ResultConnecting {
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

	if r := tcb.UpdateStateInbound(tcp); r != tcpconntrack.ResultAlive {
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

	if r := tcb.UpdateStateOutbound(tcp); r != tcpconntrack.ResultAlive {
		t.Fatalf("Bad result: got %v, want %v", r, tcpconntrack.ResultAlive)
	}
}
