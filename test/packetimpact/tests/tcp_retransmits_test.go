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

package tcp_retransmits_test

import (
	"bytes"
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

func getRTO(t *testing.T, dut testbench.DUT, acceptFd int32) (rto time.Duration) {
	info := linux.TCPInfo{}
	infoBytes := dut.GetSockOpt(t, acceptFd, unix.SOL_TCP, unix.TCP_INFO, int32(linux.SizeOfTCPInfo))
	if got, want := len(infoBytes), linux.SizeOfTCPInfo; got != want {
		t.Fatalf("unexpected size for TCP_INFO, got %d bytes want %d bytes", got, want)
	}
	binary.Unmarshal(infoBytes, usermem.ByteOrder, &info)
	return time.Duration(info.RTO) * time.Microsecond
}

// TestRetransmits tests retransmits occur at exponentially increasing
// time intervals.
func TestRetransmits(t *testing.T) {
	dut := testbench.NewDUT(t)
	listenFd, remotePort := dut.CreateListener(t, unix.SOCK_STREAM, unix.IPPROTO_TCP, 1)
	defer dut.Close(t, listenFd)
	conn := dut.Net.NewTCPIPv4(t, testbench.TCP{DstPort: &remotePort}, testbench.TCP{SrcPort: &remotePort})
	defer conn.Close(t)

	conn.Connect(t)
	acceptFd, _ := dut.Accept(t, listenFd)
	defer dut.Close(t, acceptFd)

	dut.SetSockOptInt(t, acceptFd, unix.IPPROTO_TCP, unix.TCP_NODELAY, 1)

	sampleData := []byte("Sample Data")
	samplePayload := &testbench.Payload{Bytes: sampleData}

	// Give a chance for the dut to estimate RTO with RTT from the DATA-ACK.
	// This is to reduce the test run-time from the default initial RTO of 1s.
	// TODO(gvisor.dev/issue/2685) Estimate RTO during handshake, after which
	// we can skip this data send/recv which is solely to estimate RTO.
	dut.Send(t, acceptFd, sampleData, 0)
	if _, err := conn.ExpectData(t, &testbench.TCP{}, samplePayload, time.Second); err != nil {
		t.Fatalf("expected payload was not received: %s", err)
	}
	conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck | header.TCPFlagPsh)}, samplePayload)
	if _, err := conn.ExpectData(t, &testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)}, nil, time.Second); err != nil {
		t.Fatalf("expected packet was not received: %s", err)
	}
	// Wait for the DUT to receive the data, thus ensuring that the stack has
	// estimated RTO before we query RTO via TCP_INFO.
	if got := dut.Recv(t, acceptFd, int32(len(sampleData)), 0); !bytes.Equal(got, sampleData) {
		t.Fatalf("got dut.Recv(t, %d, %d, 0) = %s, want %s", acceptFd, len(sampleData), got, sampleData)
	}

	const timeoutCorrection = time.Second
	const diffCorrection = 200 * time.Millisecond
	rto := getRTO(t, dut, acceptFd)

	dut.Send(t, acceptFd, sampleData, 0)
	seq := testbench.Uint32(uint32(*conn.RemoteSeqNum(t)))
	if _, err := conn.ExpectData(t, &testbench.TCP{SeqNum: seq}, samplePayload, rto+timeoutCorrection); err != nil {
		t.Fatalf("expected payload was not received: %s", err)
	}

	// Expect retransmits of the same segment.
	for i := 0; i < 5; i++ {
		startTime := time.Now()
		rto = getRTO(t, dut, acceptFd)
		if _, err := conn.ExpectData(t, &testbench.TCP{SeqNum: seq}, samplePayload, rto+timeoutCorrection); err != nil {
			t.Fatalf("expected payload was not received within %s loop %d err %s", rto+timeoutCorrection, i, err)
		}
		if diff := time.Since(startTime); diff+diffCorrection < rto {
			t.Fatalf("retransmit came sooner got: %s want: >= %s probe %d", diff+diffCorrection, rto, i)
		}
	}
}
