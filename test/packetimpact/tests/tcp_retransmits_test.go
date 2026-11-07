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
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

func init() {
	testbench.Initialize(flag.CommandLine)
}

// expectHandshakeRetransmit withholds the peer's ACK and waits for the same
// SYN sequence number a second time.
func expectHandshakeRetransmit(t *testing.T, conn *testbench.TCPIPv4, flags header.TCPFlags) {
	t.Helper()
	want := testbench.TCP{Flags: testbench.TCPFlags(flags)}
	first, err := conn.Expect(t, want, time.Second)
	if err != nil {
		t.Fatalf("waiting for %s: %v", flags, err)
	}
	want.SeqNum = first.SeqNum
	if _, err := conn.Expect(t, want, 3*time.Second); err != nil {
		t.Fatalf("waiting for retransmitted %s: %v", flags, err)
	}
}

func TestActiveHandshakeRetransmits(t *testing.T) {
	dut := testbench.NewDUT(t)
	fd, port := dut.CreateBoundSocket(t, unix.SOCK_STREAM|unix.SOCK_NONBLOCK, unix.IPPROTO_TCP, dut.Net.RemoteIPv4)
	defer dut.Close(t, fd)
	conn := dut.Net.NewTCPIPv4(t, testbench.TCP{DstPort: &port}, testbench.TCP{SrcPort: &port})
	defer conn.Close(t)
	dut.Connect(t, fd, conn.LocalAddr(t))
	expectHandshakeRetransmit(t, &conn, header.TCPFlagSyn)
	if got, want := dut.GetSockOptTCPInfo(t, fd).TotalRetrans, uint32(1); got != want {
		t.Errorf("TCP_INFO total retransmits in SYN-SENT = %d, want %d", got, want)
	}
}

func TestPassiveHandshakeRetransmits(t *testing.T) {
	dut := testbench.NewDUT(t)
	listener, port := dut.CreateListener(t, unix.SOCK_STREAM, unix.IPPROTO_TCP, 1)
	defer dut.Close(t, listener)
	conn := dut.Net.NewTCPIPv4(t, testbench.TCP{DstPort: &port}, testbench.TCP{SrcPort: &port})
	defer conn.Close(t)
	conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagSyn)})
	expectHandshakeRetransmit(t, &conn, header.TCPFlagSyn|header.TCPFlagAck)
	conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)})
	fd, _ := dut.Accept(t, listener)
	defer dut.Close(t, fd)
	if got, want := dut.GetSockOptTCPInfo(t, fd).TotalRetrans, uint32(1); got != want {
		t.Errorf("TCP_INFO total retransmits on accepted socket = %d, want %d", got, want)
	}
	if got, want := dut.GetSockOptTCPInfo(t, listener).TotalRetrans, uint32(0); got != want {
		t.Errorf("TCP_INFO total retransmits on listener = %d, want %d", got, want)
	}
}

func getRTO(t *testing.T, dut testbench.DUT, acceptFd int32) (rto time.Duration) {
	info := dut.GetSockOptTCPInfo(t, acceptFd)
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
	if got, want := dut.GetSockOptTCPInfo(t, acceptFd).TotalRetrans, uint32(0); got != want {
		t.Fatalf("TCP_INFO total retransmits before loss = %d, want %d", got, want)
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
	const retransmits = 5
	for i := 0; i < retransmits; i++ {
		startTime := time.Now()
		rto = getRTO(t, dut, acceptFd)
		if _, err := conn.ExpectData(t, &testbench.TCP{SeqNum: seq}, samplePayload, rto+timeoutCorrection); err != nil {
			t.Fatalf("expected payload was not received within %s loop %d err %s", rto+timeoutCorrection, i, err)
		}
		if diff := time.Since(startTime); diff+diffCorrection < rto {
			t.Fatalf("retransmit came sooner got: %s want: >= %s probe %d", diff+diffCorrection, rto, i)
		}
	}

	// Receiving the peer's data also ensures that its cumulative ACK has
	// reached the socket before we read the lifetime retransmission count.
	conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck | header.TCPFlagPsh)}, samplePayload)
	dut.Recv(t, acceptFd, int32(len(sampleData)), 0)
	if got, want := dut.GetSockOptTCPInfo(t, acceptFd).TotalRetrans, uint32(retransmits); got != want {
		t.Errorf("TCP_INFO total retransmits after ACK = %d, want %d", got, want)
	}
}
