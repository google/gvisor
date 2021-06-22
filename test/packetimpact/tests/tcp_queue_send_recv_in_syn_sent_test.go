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

package tcp_queue_send_recv_in_syn_sent_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
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

// TestQueueSendInSynSentHandshake tests send behavior when the TCP state
// is SYN-SENT and the connections is finally established.
func TestQueueSendInSynSentHandshake(t *testing.T) {
	dut := testbench.NewDUT(t)
	socket, remotePort := dut.CreateBoundSocket(t, unix.SOCK_STREAM, unix.IPPROTO_TCP, dut.Net.RemoteIPv4)
	conn := dut.Net.NewTCPIPv4(t, testbench.TCP{DstPort: &remotePort}, testbench.TCP{SrcPort: &remotePort})
	defer conn.Close(t)

	sampleData := []byte("Sample Data")

	dut.SetNonBlocking(t, socket, true)
	if _, err := dut.ConnectWithErrno(context.Background(), t, socket, conn.LocalAddr(t)); !errors.Is(err, unix.EINPROGRESS) {
		t.Fatalf("failed to bring DUT to SYN-SENT, got: %s, want EINPROGRESS", err)
	}
	if _, err := conn.Expect(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagSyn)}, time.Second); err != nil {
		t.Fatalf("expected a SYN from DUT, but got none: %s", err)
	}

	// Test blocking send.
	dut.SetNonBlocking(t, socket, false)

	start := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)

		close(start)
		// Issue SEND call in SYN-SENT, this should be queued for
		// process until the connection is established.
		if _, err := dut.SendWithErrno(context.Background(), t, socket, sampleData, 0); err != unix.Errno(0) {
			t.Errorf("failed to send on DUT: %s", err)
		}
	}()

	// Wait for the goroutine to be scheduled and before it
	// blocks on endpoint send/receive.
	<-start
	// The following sleep is used to prevent the connection
	// from being established before we are blocked: there is
	// still a small time window between we sending the RPC
	// request and the system actually being blocked.
	time.Sleep(100 * time.Millisecond)

	select {
	case <-done:
		t.Fatal("expected send to be blocked in SYN-SENT")
	default:
	}

	// Bring the connection to Established.
	conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagSyn | header.TCPFlagAck)})

	<-done

	// Expect the data from the DUT's enqueued send request.
	//
	// On Linux, this can be piggybacked with the ACK completing the
	// handshake. On gVisor, getting such a piggyback is a bit more
	// complicated because the actual data enqueuing occurs in the
	// callers of endpoint Write.
	if _, err := conn.ExpectData(t, &testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagPsh | header.TCPFlagAck)}, &testbench.Payload{Bytes: sampleData}, time.Second); err != nil {
		t.Fatalf("expected payload was not received: %s", err)
	}

	conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagPsh | header.TCPFlagAck)}, &testbench.Payload{Bytes: sampleData})
	if _, err := conn.Expect(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)}, time.Second); err != nil {
		t.Fatalf("expected an ACK from DUT, but got none: %s", err)
	}
}

// TestQueueRecvInSynSentHandshake tests recv behavior when the TCP state
// is SYN-SENT and the connections is finally established.
func TestQueueRecvInSynSentHandshake(t *testing.T) {
	dut := testbench.NewDUT(t)
	socket, remotePort := dut.CreateBoundSocket(t, unix.SOCK_STREAM, unix.IPPROTO_TCP, dut.Net.RemoteIPv4)
	conn := dut.Net.NewTCPIPv4(t, testbench.TCP{DstPort: &remotePort}, testbench.TCP{SrcPort: &remotePort})
	defer conn.Close(t)

	sampleData := []byte("Sample Data")

	dut.SetNonBlocking(t, socket, true)
	if _, err := dut.ConnectWithErrno(context.Background(), t, socket, conn.LocalAddr(t)); !errors.Is(err, unix.EINPROGRESS) {
		t.Fatalf("failed to bring DUT to SYN-SENT, got: %s, want EINPROGRESS", err)
	}
	if _, err := conn.Expect(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagSyn)}, time.Second); err != nil {
		t.Fatalf("expected a SYN from DUT, but got none: %s", err)
	}

	if _, _, err := dut.RecvWithErrno(context.Background(), t, socket, int32(len(sampleData)), 0); err != unix.EWOULDBLOCK {
		t.Fatalf("expected error %s, got %s", unix.EWOULDBLOCK, err)
	}

	// Test blocking read.
	dut.SetNonBlocking(t, socket, false)

	start := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)

		close(start)
		// Issue RECEIVE call in SYN-SENT, this should be queued for
		// process until the connection is established.
		n, buff, err := dut.RecvWithErrno(context.Background(), t, socket, int32(len(sampleData)), 0)
		if err != unix.Errno(0) {
			t.Errorf("failed to recv on DUT: %s", err)
			return
		}
		if got := buff[:n]; !bytes.Equal(got, sampleData) {
			t.Errorf("received data doesn't match, got:\n%s, want:\n%s", hex.Dump(got), hex.Dump(sampleData))
		}
	}()

	// Wait for the goroutine to be scheduled and before it
	// blocks on endpoint send/receive.
	<-start

	// The following sleep is used to prevent the connection
	// from being established before we are blocked: there is
	// still a small time window between we sending the RPC
	// request and the system actually being blocked.
	time.Sleep(100 * time.Millisecond)

	// Bring the connection to Established.
	conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagSyn | header.TCPFlagAck)})
	if _, err := conn.Expect(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)}, time.Second); err != nil {
		t.Fatalf("expected an ACK from DUT, but got none: %s", err)
	}

	// Send sample payload so that DUT can recv.
	conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagPsh | header.TCPFlagAck)}, &testbench.Payload{Bytes: sampleData})
	if _, err := conn.Expect(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)}, time.Second); err != nil {
		t.Fatalf("expected an ACK from DUT, but got none: %s", err)
	}

	<-done
}

// TestQueueSendInSynSentRST tests send behavior when the TCP state
// is SYN-SENT and an RST is sent.
func TestQueueSendInSynSentRST(t *testing.T) {
	dut := testbench.NewDUT(t)
	socket, remotePort := dut.CreateBoundSocket(t, unix.SOCK_STREAM, unix.IPPROTO_TCP, dut.Net.RemoteIPv4)
	conn := dut.Net.NewTCPIPv4(t, testbench.TCP{DstPort: &remotePort}, testbench.TCP{SrcPort: &remotePort})
	defer conn.Close(t)

	sampleData := []byte("Sample Data")

	dut.SetNonBlocking(t, socket, true)
	if _, err := dut.ConnectWithErrno(context.Background(), t, socket, conn.LocalAddr(t)); !errors.Is(err, unix.EINPROGRESS) {
		t.Fatalf("failed to bring DUT to SYN-SENT, got: %s, want EINPROGRESS", err)
	}
	if _, err := conn.Expect(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagSyn)}, time.Second); err != nil {
		t.Fatalf("expected a SYN from DUT, but got none: %s", err)
	}

	// Test blocking send.
	dut.SetNonBlocking(t, socket, false)

	start := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)

		close(start)
		// Issue SEND call in SYN-SENT, this should be queued for
		// process until the connection is established.
		n, err := dut.SendWithErrno(context.Background(), t, socket, sampleData, 0)
		if err != unix.ECONNREFUSED {
			t.Errorf("expected error %s, got %s", unix.ECONNREFUSED, err)
		}
		if n != -1 {
			t.Errorf("expected return value %d, got %d", -1, n)
		}
	}()

	// Wait for the goroutine to be scheduled and before it
	// blocks on endpoint send/receive.
	<-start

	// The following sleep is used to prevent the connection
	// from being established before we are blocked: there is
	// still a small time window between we sending the RPC
	// request and the system actually being blocked.
	time.Sleep(100 * time.Millisecond)

	select {
	case <-done:
		t.Fatal("expected send to be blocked in SYN-SENT")
	default:
	}

	conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagRst | header.TCPFlagAck)})

	<-done
}

// TestQueueRecvInSynSentRST tests recv behavior when the TCP state
// is SYN-SENT and an RST is sent.
func TestQueueRecvInSynSentRST(t *testing.T) {
	dut := testbench.NewDUT(t)
	socket, remotePort := dut.CreateBoundSocket(t, unix.SOCK_STREAM, unix.IPPROTO_TCP, dut.Net.RemoteIPv4)
	conn := dut.Net.NewTCPIPv4(t, testbench.TCP{DstPort: &remotePort}, testbench.TCP{SrcPort: &remotePort})
	defer conn.Close(t)

	sampleData := []byte("Sample Data")

	dut.SetNonBlocking(t, socket, true)
	if _, err := dut.ConnectWithErrno(context.Background(), t, socket, conn.LocalAddr(t)); !errors.Is(err, unix.EINPROGRESS) {
		t.Fatalf("failed to bring DUT to SYN-SENT, got: %s, want EINPROGRESS", err)
	}
	if _, err := conn.Expect(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagSyn)}, time.Second); err != nil {
		t.Fatalf("expected a SYN from DUT, but got none: %s", err)
	}

	if _, _, err := dut.RecvWithErrno(context.Background(), t, socket, int32(len(sampleData)), 0); err != unix.EWOULDBLOCK {
		t.Fatalf("expected error %s, got %s", unix.EWOULDBLOCK, err)
	}

	// Test blocking read.
	dut.SetNonBlocking(t, socket, false)

	start := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)

		close(start)
		// Issue RECEIVE call in SYN-SENT, this should be queued for
		// process until the connection is established.
		n, _, err := dut.RecvWithErrno(context.Background(), t, socket, int32(len(sampleData)), 0)
		if err != unix.ECONNREFUSED {
			t.Errorf("expected error %s, got %s", unix.ECONNREFUSED, err)
		}
		if n != -1 {
			t.Errorf("expected return value %d, got %d", -1, n)
		}
	}()

	// Wait for the goroutine to be scheduled and before it
	// blocks on endpoint send/receive.
	<-start

	// The following sleep is used to prevent the connection
	// from being established before we are blocked: there is
	// still a small time window between we sending the RPC
	// request and the system actually being blocked.
	time.Sleep(100 * time.Millisecond)

	conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagRst | header.TCPFlagAck)})
	<-done
}
