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
	"gvisor.dev/gvisor/pkg/binary"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

func init() {
	testbench.Initialize(flag.CommandLine)
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
		t.Fatalf("expected a packet with payload %v: %s", samplePayload, err)
	}
	conn.Send(t, testbench.TCP{Flags: testbench.Uint8(header.TCPFlagAck)})

	info := linux.TCPInfo{}
	infoBytes := dut.GetSockOpt(t, acceptFD, unix.SOL_TCP, unix.TCP_INFO, int32(linux.SizeOfTCPInfo))
	binary.Unmarshal(infoBytes, usermem.ByteOrder, &info)

	rtt := time.Duration(info.RTT) * time.Microsecond
	rttvar := time.Duration(info.RTTVar) * time.Microsecond
	rto := time.Duration(info.RTO) * time.Microsecond
	if rtt == 0 || rttvar == 0 || rto == 0 {
		t.Errorf("expected rtt(%v), rttvar(%v) and rto(%v) to be greater than zero", rtt, rttvar, rto)
	}
	if info.ReordSeen != 0 {
		t.Errorf("expected the connection to not have any reordering, got: %v want: 0", info.ReordSeen)
	}
	if info.SndCwnd == 0 {
		t.Errorf("expected send congestion window to be greater than zero")
	}
	if info.CaState != linux.TCP_CA_Open {
		t.Errorf("expected the connection to be in open state, got: %v want: %v", info.CaState, linux.TCP_CA_Open)
	}

	if t.Failed() {
		t.FailNow()
	}

	// Check the congestion control state and send congestion window after
	// retransmission timeout.
	seq := testbench.Uint32(uint32(*conn.RemoteSeqNum(t)))
	dut.Send(t, acceptFD, sampleData, 0)
	if _, err := conn.ExpectData(t, &testbench.TCP{}, samplePayload, time.Second); err != nil {
		t.Fatalf("expected a packet with payload %v: %s", samplePayload, err)
	}

	// Expect retransmission of the packet within 1.5*RTO.
	timeout := time.Duration(float64(info.RTO)*1.5) * time.Microsecond
	if _, err := conn.ExpectData(t, &testbench.TCP{SeqNum: seq}, samplePayload, timeout); err != nil {
		t.Fatalf("expected a packet with payload %v: %s", samplePayload, err)
	}

	info = linux.TCPInfo{}
	infoBytes = dut.GetSockOpt(t, acceptFD, unix.SOL_TCP, unix.TCP_INFO, int32(linux.SizeOfTCPInfo))
	binary.Unmarshal(infoBytes, usermem.ByteOrder, &info)
	if info.CaState != linux.TCP_CA_Loss {
		t.Errorf("expected the connection to be in loss recovery, got: %v want: %v", info.CaState, linux.TCP_CA_Loss)
	}
	if info.SndCwnd != 1 {
		t.Errorf("expected send congestion window to be 1, got: %v %v", info.SndCwnd)
	}
}
