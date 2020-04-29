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

package udp_icmp_error_propagation_test

import (
	"context"
	"fmt"
	"net"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	tb "gvisor.dev/gvisor/test/packetimpact/testbench"
)

type connected bool

func (c connected) String() string {
	if c {
		return "Connected"
	}
	return "Connectionless"
}

type icmpError int

const (
	portUnreachable icmpError = iota
	timeToLiveExceeded
)

func (e icmpError) String() string {
	switch e {
	case portUnreachable:
		return "PortUnreachable"
	case timeToLiveExceeded:
		return "TimeToLiveExpired"
	}
	return "Unknown ICMP error"
}

func (e icmpError) ToICMPv4() *tb.ICMPv4 {
	switch e {
	case portUnreachable:
		return &tb.ICMPv4{Type: tb.ICMPv4Type(header.ICMPv4DstUnreachable), Code: tb.Uint8(header.ICMPv4PortUnreachable)}
	case timeToLiveExceeded:
		return &tb.ICMPv4{Type: tb.ICMPv4Type(header.ICMPv4TimeExceeded), Code: tb.Uint8(header.ICMPv4TTLExceeded)}
	}
	return nil
}

type errorDetectionFunc func(context.Context, *tb.DUT, *tb.UDPIPv4, int32, syscall.Errno) error

// testRecv tests observing the ICMP error through the recv syscall.
// A packet is sent to the DUT, and if wantErrno is non-zero, then the first
// recv should fail and the second should succeed. Otherwise if wantErrno is
// zero then the first recv should succeed immediately.
func testRecv(ctx context.Context, dut *tb.DUT, conn *tb.UDPIPv4, remoteFD int32, wantErrno syscall.Errno) error {
	conn.Send(tb.UDP{})

	if wantErrno != syscall.Errno(0) {
		ctx, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		ret, _, err := dut.RecvWithErrno(ctx, remoteFD, 100, 0)
		if ret != -1 {
			return fmt.Errorf("recv after ICMP error succeeded unexpectedly, expected (%[1]d) %[1]v", wantErrno)
		}
		if err != wantErrno {
			return fmt.Errorf("recv after ICMP error resulted in error (%[1]d) %[1]v, expected (%[2]d) %[2]v", err, wantErrno)
		}
	}

	dut.Recv(remoteFD, 100, 0)
	return nil
}

// testSendTo tests observing the ICMP error through the send syscall.
// If wantErrno is non-zero, the first send should fail and a subsequent send
// should suceed; while if wantErrno is zero then the first send should just
// succeed.
func testSendTo(ctx context.Context, dut *tb.DUT, conn *tb.UDPIPv4, remoteFD int32, wantErrno syscall.Errno) error {
	if wantErrno != syscall.Errno(0) {
		ctx, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		ret, err := dut.SendToWithErrno(ctx, remoteFD, nil, 0, conn.LocalAddr())

		if ret != -1 {
			return fmt.Errorf("sendto after ICMP error succeeded unexpectedly, expected (%[1]d) %[1]v", wantErrno)
		}
		if err != wantErrno {
			return fmt.Errorf("sendto after ICMP error resulted in error (%[1]d) %[1]v, expected (%[2]d) %[2]v", err, wantErrno)
		}
	}

	dut.SendTo(remoteFD, nil, 0, conn.LocalAddr())
	if _, err := conn.Expect(tb.UDP{}, time.Second); err != nil {
		return fmt.Errorf("did not receive UDP packet as expected: %s", err)
	}
	return nil
}

func testSockOpt(_ context.Context, dut *tb.DUT, conn *tb.UDPIPv4, remoteFD int32, wantErrno syscall.Errno) error {
	errno := syscall.Errno(dut.GetSockOptInt(remoteFD, unix.SOL_SOCKET, unix.SO_ERROR))
	if errno != wantErrno {
		return fmt.Errorf("SO_ERROR sockopt after ICMP error is (%[1]d) %[1]v, expected (%[2]d) %[2]v", errno, wantErrno)
	}

	// Check that after clearing socket error, sending doesn't fail.
	dut.SendTo(remoteFD, nil, 0, conn.LocalAddr())
	if _, err := conn.Expect(tb.UDP{}, time.Second); err != nil {
		return fmt.Errorf("did not receive UDP packet as expected: %s", err)
	}
	return nil
}

type testParameters struct {
	connected connected
	icmpErr   icmpError
	wantErrno syscall.Errno
	f         errorDetectionFunc
	fName     string
}

// TestUDPICMPErrorPropagation tests that ICMP PortUnreachable error messages
// destined for a "connected" UDP socket are observable on said socket by:
// 1. causing the next send to fail with ECONNREFUSED,
// 2. causing the next recv to fail with ECONNREFUSED, or
// 3. returning ECONNREFUSED through the SO_ERROR socket option.
func TestUDPICMPErrorPropagation(t *testing.T) {
	var testCases []testParameters
	for _, c := range []connected{true, false} {
		for _, i := range []icmpError{portUnreachable, timeToLiveExceeded} {
			e := syscall.Errno(0)
			if c && i == portUnreachable {
				e = unix.ECONNREFUSED
			}
			for _, f := range []struct {
				name string
				f    errorDetectionFunc
			}{
				{"SendTo", testSendTo},
				{"Recv", testRecv},
				{"SockOpt", testSockOpt},
			} {
				testCases = append(testCases, testParameters{c, i, e, f.f, f.name})
			}
		}
	}

	for _, tt := range testCases {
		t.Run(fmt.Sprintf("%s/%s/%s", tt.connected, tt.icmpErr, tt.fName), func(t *testing.T) {
			dut := tb.NewDUT(t)
			defer dut.TearDown()

			remoteFD, remotePort := dut.CreateBoundSocket(unix.SOCK_DGRAM, unix.IPPROTO_UDP, net.ParseIP("0.0.0.0"))
			defer dut.Close(remoteFD)

			conn := tb.NewUDPIPv4(t, tb.UDP{DstPort: &remotePort}, tb.UDP{SrcPort: &remotePort})
			defer conn.Close()

			if tt.connected {
				dut.Connect(remoteFD, conn.LocalAddr())
			}

			dut.SendTo(remoteFD, nil, 0, conn.LocalAddr())
			udp, err := conn.Expect(tb.UDP{}, time.Second)
			if err != nil {
				t.Fatalf("did not receive message from DUT: %s", err)
			}

			if tt.icmpErr == timeToLiveExceeded {
				ip, ok := udp.Prev().(*tb.IPv4)
				if !ok {
					t.Fatalf("expected %s to be IPv4", udp.Prev())
				}
				*ip.TTL = 1
				// Let serialization recalculate the checksum since we set the
				// TTL to 1.
				ip.Checksum = nil

				// Note that the ICMP payload is valid in this case because the UDP
				// payload is empty. If the UDP payload were not empty, the packet
				// length during serialization may not be calculated correctly,
				// resulting in a mal-formed packet.
				conn.SendIP(tt.icmpErr.ToICMPv4(), ip, udp)
			} else {
				conn.SendIP(tt.icmpErr.ToICMPv4(), udp.Prev(), udp)
			}

			if err := tt.f(context.Background(), &dut, &conn, remoteFD, tt.wantErrno); err != nil {
				t.Fatal(err)
			}
		})
	}
}
