// Copyright 2020 The gVisor Authors.
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

package tcp_info_test

import (
	"flag"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

func init() {
	testbench.Initialize(flag.CommandLine)
}

func TestTCPInfoOptions(t *testing.T) {
	dut := testbench.NewDUT(t)
	listenFD, port := dut.CreateListener(t, unix.SOCK_STREAM, unix.IPPROTO_TCP, 1)
	defer dut.Close(t, listenFD)

	const mask = linux.TCPI_OPT_TIMESTAMPS | linux.TCPI_OPT_SACK
	for _, tt := range []struct {
		name string
		want uint8
	}{
		{"Neither", 0},
		{"Timestamps", linux.TCPI_OPT_TIMESTAMPS},
		{"SACK", linux.TCPI_OPT_SACK},
		{"Both", mask},
	} {
		t.Run(tt.name, func(t *testing.T) {
			conn := dut.Net.NewTCPIPv4(t, testbench.TCP{DstPort: &port}, testbench.TCP{SrcPort: &port})
			defer conn.Close(t)
			var opts [header.TCPOptionsMaximumSize]byte
			n := 0
			ts, sack := tt.want&linux.TCPI_OPT_TIMESTAMPS != 0, tt.want&linux.TCPI_OPT_SACK != 0
			if ts {
				n += header.EncodeTSOption(1, 0, opts[n:])
			}
			if sack {
				n += header.EncodeSACKPermittedOption(opts[n:])
			}
			conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagSyn), Options: opts[:n]})
			synAck, err := conn.Expect(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagSyn | header.TCPFlagAck)}, time.Second)
			if err != nil {
				t.Fatalf("expect SYN-ACK: %v", err)
			}
			negotiated := header.ParseSynOptions(synAck.Options, true /* isAck */)
			if negotiated.TS != ts || negotiated.SACKPermitted != sack {
				t.Fatalf("SYN-ACK timestamps=%t SACK=%t, want %t and %t", negotiated.TS, negotiated.SACKPermitted, ts, sack)
			}
			n = 0
			if negotiated.TS {
				n = header.EncodeTSOption(2, negotiated.TSVal, opts[:])
			}
			conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck), Options: opts[:n]})
			dut.PollOne(t, listenFD, unix.POLLIN, time.Second)
			fd, _ := dut.Accept(t, listenFD)
			defer dut.Close(t, fd)
			if got := dut.GetSockOptTCPInfo(t, fd).Options & mask; got != tt.want {
				t.Errorf("TCP_INFO timestamps/SACK bits = %#x, want %#x from SYN-ACK", got, tt.want)
			}
		})
	}
}

func TestTCPInfo(t *testing.T) {
	// Create a socket, listen, TCP connect, and accept.
	dut := testbench.NewDUT(t)
	listenFD, remotePort := dut.CreateListener(t, unix.SOCK_STREAM, unix.IPPROTO_TCP, 1)
	defer dut.Close(t, listenFD)

	conn := dut.Net.NewTCPIPv4(t, testbench.TCP{DstPort: &remotePort}, testbench.TCP{SrcPort: &remotePort})
	defer conn.Close(t)
	conn.Connect(t)

	acceptFD, _ := dut.Accept(t, listenFD)
	defer dut.Close(t, acceptFD)

	// Send and receive sample data.
	sampleData := []byte("Sample Data")
	samplePayload := &testbench.Payload{Bytes: sampleData}
	dut.Send(t, acceptFD, sampleData, 0)
	if _, err := conn.ExpectData(t, &testbench.TCP{}, samplePayload, time.Second); err != nil {
		t.Fatalf("expected a packet with payload %s: %s", samplePayload, err)
	}
	conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)})

	info := dut.GetSockOptTCPInfo(t, acceptFD)
	if got, want := uint32(info.State), linux.TCP_ESTABLISHED; got != want {
		t.Fatalf("got %d want %d", got, want)
	}
	if info.RTT == 0 {
		t.Errorf("got RTT=0, want nonzero")
	}
	if info.RTTVar == 0 {
		t.Errorf("got RTTVar=0, want nonzero")
	}
	if info.RTO == 0 {
		t.Errorf("got RTO=0, want nonzero")
	}
	if info.ReordSeen != 0 {
		t.Errorf("expected the connection to not have any reordering, got: %d want: 0", info.ReordSeen)
	}
	if info.SndCwnd == 0 {
		t.Errorf("expected send congestion window to be greater than zero")
	}
	if info.CaState != linux.TCP_CA_Open {
		t.Errorf("expected the connection to be in open state, got: %d want: %d", info.CaState, linux.TCP_CA_Open)
	}

	if t.Failed() {
		t.FailNow()
	}

	// Check the congestion control state and send congestion window after
	// retransmission timeout.
	seq := testbench.Uint32(uint32(*conn.RemoteSeqNum(t)))
	dut.Send(t, acceptFD, sampleData, 0)
	if _, err := conn.ExpectData(t, &testbench.TCP{}, samplePayload, time.Second); err != nil {
		t.Fatalf("expected a packet with payload %s: %s", samplePayload, err)
	}

	// Given a generous retransmission timeout.
	timeout := time.Duration(info.RTO) * 2 * time.Microsecond
	if _, err := conn.ExpectData(t, &testbench.TCP{SeqNum: seq}, samplePayload, timeout); err != nil {
		t.Fatalf("expected a packet with payload %s: %s", samplePayload, err)
	}

	info = dut.GetSockOptTCPInfo(t, acceptFD)
	if info.CaState != linux.TCP_CA_Loss {
		t.Errorf("expected the connection to be in loss recovery, got: %d want: %d", info.CaState, linux.TCP_CA_Loss)
	}
	if info.SndCwnd != 1 {
		t.Errorf("expected send congestion window to be 1, got: %d", info.SndCwnd)
	}
}
