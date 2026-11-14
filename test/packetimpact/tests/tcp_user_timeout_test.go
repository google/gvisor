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

package tcp_user_timeout_test

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

func sendPayload(t *testing.T, conn *testbench.TCPIPv4, dut *testbench.DUT, fd int32) {
	sampleData := make([]byte, 100)
	for i := range sampleData {
		sampleData[i] = uint8(i)
	}
	conn.Drain(t)
	dut.Send(t, fd, sampleData, 0)
	if _, err := conn.ExpectData(t, &testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck | header.TCPFlagPsh)}, &testbench.Payload{Bytes: sampleData}, time.Second); err != nil {
		t.Fatalf("expected data but got none: %w", err)
	}
}

func sendFIN(t *testing.T, conn *testbench.TCPIPv4, dut *testbench.DUT, fd int32) {
	dut.Close(t, fd)
}

func TestTCPUserTimeout(t *testing.T) {
	for _, tt := range []struct {
		description string
		userTimeout time.Duration
		sendDelay   time.Duration
	}{
		{"NoUserTimeout", 0, 3 * time.Second},
		{"ACKBeforeUserTimeout", 5 * time.Second, 4 * time.Second},
		{"ACKAfterUserTimeout", 5 * time.Second, 7 * time.Second},
	} {
		for _, ttf := range []struct {
			description string
			f           func(_ *testing.T, _ *testbench.TCPIPv4, _ *testbench.DUT, fd int32)
		}{
			{"AfterPayload", sendPayload},
			{"AfterFIN", sendFIN},
		} {
			t.Run(tt.description+ttf.description, func(t *testing.T) {
				// Create a socket, listen, TCP handshake, and accept.
				dut := testbench.NewDUT(t)
				listenFD, remotePort := dut.CreateListener(t, unix.SOCK_STREAM, unix.IPPROTO_TCP, 1)
				defer dut.Close(t, listenFD)
				conn := dut.Net.NewTCPIPv4(t, testbench.TCP{DstPort: &remotePort}, testbench.TCP{SrcPort: &remotePort})
				defer conn.Close(t)
				conn.Connect(t)
				acceptFD, _ := dut.Accept(t, listenFD)

				if tt.userTimeout != 0 {
					dut.SetSockOptInt(t, acceptFD, unix.SOL_TCP, unix.TCP_USER_TIMEOUT, int32(tt.userTimeout.Milliseconds()))
				}

				ttf.f(t, &conn, &dut, acceptFD)

				time.Sleep(tt.sendDelay)
				conn.Drain(t)
				conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)})

				// If TCP_USER_TIMEOUT was set and the above delay was longer than the
				// TCP_USER_TIMEOUT then the DUT should send a RST in response to the
				// testbench's packet.
				expectRST := tt.userTimeout != 0 && tt.sendDelay > tt.userTimeout
				expectTimeout := 5 * time.Second
				got, err := conn.Expect(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagRst)}, expectTimeout)
				if expectRST && err != nil {
					t.Errorf("expected RST packet within %s but got none: %s", expectTimeout, err)
				}
				if !expectRST && got != nil {
					t.Errorf("expected no RST packet within %s but got one: %s", expectTimeout, got)
				}
			})
		}
	}
}

// TestUserTimeoutOnNextFlight leaves fresh data outstanding when the peer
// acknowledges the complete window that was in flight at the prior timeout.
func TestUserTimeoutOnNextFlight(t *testing.T) {
	t.Run("beforeNextRTO", func(t *testing.T) { testUserTimeoutOnNextFlight(t, false) })
	t.Run("afterNextRTO", func(t *testing.T) { testUserTimeoutOnNextFlight(t, true) })
}

func testUserTimeoutOnNextFlight(t *testing.T, retryOldest bool) {
	dut := testbench.NewDUT(t)
	listener, port := dut.CreateListener(t, unix.SOCK_STREAM, unix.IPPROTO_TCP, 1)
	defer dut.Close(t, listener)
	conn := dut.Net.NewTCPIPv4(t, testbench.TCP{DstPort: &port}, testbench.TCP{SrcPort: &port})
	defer conn.Close(t)
	const mss = 512
	conn.ConnectWithOptions(t, []byte{header.TCPOptionMSS, 4, mss >> 8, mss & 255})
	fd, _ := dut.Accept(t, listener)
	defer dut.Close(t, fd)
	dut.SetSockOptInt(t, fd, unix.IPPROTO_TCP, unix.TCP_NODELAY, 1)
	base := uint32(*conn.RemoteSeqNum(t))
	send := func(ch byte) {
		t.Helper()
		if n := dut.Send(t, fd, bytes.Repeat([]byte{ch}, mss), 0); n != mss {
			t.Fatalf("Send(%c)=%d, want %d", ch, n, mss)
		}
	}
	expect := func(ch byte, offset int, within time.Duration) {
		t.Helper()
		if _, err := conn.ExpectData(t, &testbench.TCP{SeqNum: testbench.Uint32(base + uint32(offset))}, &testbench.Payload{Bytes: bytes.Repeat([]byte{ch}, mss)}, within); err != nil {
			t.Fatalf("waiting for %c at %d: %v", ch, offset, err)
		}
	}
	ack := func(size int) {
		conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck), AckNum: testbench.Uint32(base + uint32(size))})
	}
	send('w')
	expect('w', 0, time.Second)
	time.Sleep(30 * time.Millisecond)
	ack(mss)
	base += mss
	wait := time.Now().Add(time.Second)
	for {
		info := dut.GetSockOptTCPInfo(t, fd)
		if info.Unacked == 0 {
			break
		}
		if time.Now().After(wait) {
			t.Fatal("warm-up data still outstanding")
		}
		time.Sleep(time.Millisecond)
	}
	rto := time.Duration(dut.GetSockOptTCPInfo(t, fd).RTO) * time.Microsecond
	if rto < 50*time.Millisecond || rto > 2*time.Second {
		t.Fatalf("unexpected starting RTO: %s", rto)
	}
	uto := 4 * rto
	if retryOldest {
		uto = 8 * rto
	}
	dut.SetSockOptInt(t, fd, unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT, int32(uto.Milliseconds()))
	t0 := time.Now()
	send('a')
	expect('a', 0, time.Second)
	send('b')
	expect('b', mss, time.Second)
	expect('a', 0, 2*rto+time.Second)
	// The sender's window fell to one segment. Queue c now so the ACK
	// for a can send c while b remains in the old recovery window.
	send('c')
	expect('a', 0, 3*rto+time.Second)
	ack(mss)
	expect('c', 2*mss, 3*rto)
	fresh := time.Since(t0)
	if retryOldest {
		// A further RTO retransmits b while c is already outstanding.
		expect('b', mss, 6*rto)
		if elapsed := time.Since(t0) - fresh; elapsed < rto/2 {
			t.Fatalf("b arrived %s after c, before another RTO", elapsed)
		}
		// There is less than one initial RTO left before the old user
		// timeout. The actual RTO must still reflect the backoff.
		if got := time.Duration(dut.GetSockOptTCPInfo(t, fd).RTO) * time.Microsecond; got < 2*rto {
			t.Fatalf("RTO after retransmitting b = %s, want at least %s", got, 2*rto)
		}
	}
	ack(2 * mss)
	checkAt := t0.Add(uto + 3*rto/2)
	if time.Until(checkAt) <= 0 || checkAt.Sub(t0.Add(fresh)) >= uto {
		t.Fatalf("no disjoint old/new deadline: fresh=%s, check=%s, timeout=%s", fresh, checkAt.Sub(t0), uto)
	}
	time.Sleep(time.Until(checkAt))
	errno := dut.GetSockOptInt(t, fd, unix.SOL_SOCKET, unix.SO_ERROR)
	if errno != 0 {
		t.Fatalf("SO_ERROR=%d (%s) on new flight", errno, unix.Errno(errno))
	}
	ack(3 * mss)
	send('d')
	expect('d', 3*mss, time.Second)
	ack(4 * mss)
}
