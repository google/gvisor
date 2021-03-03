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
	"flag"
	"fmt"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

func init() {
	testbench.Initialize(flag.CommandLine)
}

type connectionMode bool

func (c connectionMode) String() string {
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

func (e icmpError) ToICMPv4() *testbench.ICMPv4 {
	switch e {
	case portUnreachable:
		return &testbench.ICMPv4{
			Type: testbench.ICMPv4Type(header.ICMPv4DstUnreachable),
			Code: testbench.ICMPv4Code(header.ICMPv4PortUnreachable)}
	case timeToLiveExceeded:
		return &testbench.ICMPv4{
			Type: testbench.ICMPv4Type(header.ICMPv4TimeExceeded),
			Code: testbench.ICMPv4Code(header.ICMPv4TTLExceeded)}
	}
	return nil
}

type errorDetection struct {
	name         string
	useValidConn bool
	f            func(context.Context, *testing.T, testData)
}

type testData struct {
	dut        *testbench.DUT
	conn       *testbench.UDPIPv4
	remoteFD   int32
	remotePort uint16
	cleanFD    int32
	cleanPort  uint16
	wantErrno  syscall.Errno
}

// wantErrno computes the errno to expect given the connection mode of a UDP
// socket and the ICMP error it will receive.
func wantErrno(c connectionMode, icmpErr icmpError) syscall.Errno {
	if c && icmpErr == portUnreachable {
		return syscall.Errno(unix.ECONNREFUSED)
	}
	return syscall.Errno(0)
}

// sendICMPError sends an ICMP error message in response to a UDP datagram.
func sendICMPError(t *testing.T, conn *testbench.UDPIPv4, icmpErr icmpError, udp *testbench.UDP) {
	t.Helper()

	layers := conn.CreateFrame(t, nil)
	layers = layers[:len(layers)-1]
	ip, ok := udp.Prev().(*testbench.IPv4)
	if !ok {
		t.Fatalf("expected %s to be IPv4", udp.Prev())
	}
	if icmpErr == timeToLiveExceeded {
		*ip.TTL = 1
		// Let serialization recalculate the checksum since we set the TTL
		// to 1.
		ip.Checksum = nil
	}
	// Note that the ICMP payload is valid in this case because the UDP
	// payload is empty. If the UDP payload were not empty, the packet
	// length during serialization may not be calculated correctly,
	// resulting in a mal-formed packet.
	layers = append(layers, icmpErr.ToICMPv4(), ip, udp)

	conn.SendFrameStateless(t, layers)
}

// testRecv tests observing the ICMP error through the recv syscall. A packet
// is sent to the DUT, and if wantErrno is non-zero, then the first recv should
// fail and the second should succeed. Otherwise if wantErrno is zero then the
// first recv should succeed immediately.
func testRecv(ctx context.Context, t *testing.T, d testData) {
	t.Helper()

	// Check that receiving on the clean socket works.
	d.conn.Send(t, testbench.UDP{DstPort: &d.cleanPort})
	d.dut.Recv(t, d.cleanFD, 100, 0)

	d.conn.Send(t, testbench.UDP{})

	if d.wantErrno != syscall.Errno(0) {
		ctx, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		ret, _, err := d.dut.RecvWithErrno(ctx, t, d.remoteFD, 100, 0)
		if ret != -1 {
			t.Fatalf("recv after ICMP error succeeded unexpectedly, expected (%[1]d) %[1]v", d.wantErrno)
		}
		if err != d.wantErrno {
			t.Fatalf("recv after ICMP error resulted in error (%[1]d) %[1]v, expected (%[2]d) %[2]v", err, d.wantErrno)
		}
	}

	d.dut.Recv(t, d.remoteFD, 100, 0)
}

// testSendTo tests observing the ICMP error through the send syscall. If
// wantErrno is non-zero, the first send should fail and a subsequent send
// should suceed; while if wantErrno is zero then the first send should just
// succeed.
func testSendTo(ctx context.Context, t *testing.T, d testData) {
	// Check that sending on the clean socket works.
	d.dut.SendTo(t, d.cleanFD, nil, 0, d.conn.LocalAddr(t))
	if _, err := d.conn.Expect(t, testbench.UDP{SrcPort: &d.cleanPort}, time.Second); err != nil {
		t.Fatalf("did not receive UDP packet from clean socket on DUT: %s", err)
	}

	if d.wantErrno != syscall.Errno(0) {
		ctx, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		ret, err := d.dut.SendToWithErrno(ctx, t, d.remoteFD, nil, 0, d.conn.LocalAddr(t))

		if ret != -1 {
			t.Fatalf("sendto after ICMP error succeeded unexpectedly, expected (%[1]d) %[1]v", d.wantErrno)
		}
		if err != d.wantErrno {
			t.Fatalf("sendto after ICMP error resulted in error (%[1]d) %[1]v, expected (%[2]d) %[2]v", err, d.wantErrno)
		}
	}

	d.dut.SendTo(t, d.remoteFD, nil, 0, d.conn.LocalAddr(t))
	if _, err := d.conn.Expect(t, testbench.UDP{}, time.Second); err != nil {
		t.Fatalf("did not receive UDP packet as expected: %s", err)
	}
}

func testSockOpt(_ context.Context, t *testing.T, d testData) {
	// Check that there's no pending error on the clean socket.
	if errno := syscall.Errno(d.dut.GetSockOptInt(t, d.cleanFD, unix.SOL_SOCKET, unix.SO_ERROR)); errno != syscall.Errno(0) {
		t.Fatalf("unexpected error (%[1]d) %[1]v on clean socket", errno)
	}

	if errno := syscall.Errno(d.dut.GetSockOptInt(t, d.remoteFD, unix.SOL_SOCKET, unix.SO_ERROR)); errno != d.wantErrno {
		t.Fatalf("SO_ERROR sockopt after ICMP error is (%[1]d) %[1]v, expected (%[2]d) %[2]v", errno, d.wantErrno)
	}

	// Check that after clearing socket error, sending doesn't fail.
	d.dut.SendTo(t, d.remoteFD, nil, 0, d.conn.LocalAddr(t))
	if _, err := d.conn.Expect(t, testbench.UDP{}, time.Second); err != nil {
		t.Fatalf("did not receive UDP packet as expected: %s", err)
	}
}

// TestUDPICMPErrorPropagation tests that ICMP error messages in response to
// UDP datagrams are processed correctly. RFC 1122 section 4.1.3.3 states that:
// "UDP MUST pass to the application layer all ICMP error messages that it
// receives from the IP layer."
//
// The test cases are parametrized in 3 dimensions: 1. the UDP socket is either
// put into connection mode or left connectionless, 2. the ICMP message type
// and code, and 3. the method by which the ICMP error is observed on the
// socket: sendto, recv, or getsockopt(SO_ERROR).
//
// Linux's udp(7) man page states: "All fatal errors will be passed to the user
// as an error return even when the socket is not connected. This includes
// asynchronous errors received from the network." In practice, the only
// combination of parameters to the test that causes an error to be observable
// on the UDP socket is receiving a port unreachable message on a connected
// socket.
func TestUDPICMPErrorPropagation(t *testing.T) {
	for _, connect := range []connectionMode{true, false} {
		for _, icmpErr := range []icmpError{portUnreachable, timeToLiveExceeded} {
			wantErrno := wantErrno(connect, icmpErr)

			for _, errDetect := range []errorDetection{
				{"SendTo", false, testSendTo},
				// Send to an address that's different from the one that caused an ICMP
				// error to be returned.
				{"SendToValid", true, testSendTo},
				{"Recv", false, testRecv},
				{"SockOpt", false, testSockOpt},
			} {
				t.Run(fmt.Sprintf("%s/%s/%s", connect, icmpErr, errDetect.name), func(t *testing.T) {
					dut := testbench.NewDUT(t)

					remoteFD, remotePort := dut.CreateBoundSocket(t, unix.SOCK_DGRAM, unix.IPPROTO_UDP, net.IPv4zero)
					defer dut.Close(t, remoteFD)

					// Create a second, clean socket on the DUT to ensure that the ICMP
					// error messages only affect the sockets they are intended for.
					cleanFD, cleanPort := dut.CreateBoundSocket(t, unix.SOCK_DGRAM, unix.IPPROTO_UDP, net.IPv4zero)
					defer dut.Close(t, cleanFD)

					conn := dut.Net.NewUDPIPv4(t, testbench.UDP{DstPort: &remotePort}, testbench.UDP{SrcPort: &remotePort})
					defer conn.Close(t)

					if connect {
						dut.Connect(t, remoteFD, conn.LocalAddr(t))
						dut.Connect(t, cleanFD, conn.LocalAddr(t))
					}

					dut.SendTo(t, remoteFD, nil, 0, conn.LocalAddr(t))
					udp, err := conn.Expect(t, testbench.UDP{}, time.Second)
					if err != nil {
						t.Fatalf("did not receive message from DUT: %s", err)
					}

					sendICMPError(t, &conn, icmpErr, udp)

					errDetectConn := &conn
					if errDetect.useValidConn {
						// connClean is a UDP socket on the test runner that was not
						// involved in the generation of the ICMP error. As such,
						// interactions between it and the the DUT should be independent of
						// the ICMP error at least at the port level.
						connClean := dut.Net.NewUDPIPv4(t, testbench.UDP{DstPort: &remotePort}, testbench.UDP{SrcPort: &remotePort})
						defer connClean.Close(t)

						errDetectConn = &connClean
					}

					errDetect.f(context.Background(), t, testData{&dut, errDetectConn, remoteFD, remotePort, cleanFD, cleanPort, wantErrno})
				})
			}
		}
	}
}

// TestICMPErrorDuringUDPRecv tests behavior when a UDP socket is in the middle
// of a blocking recv and receives an ICMP error.
func TestICMPErrorDuringUDPRecv(t *testing.T) {
	for _, connect := range []connectionMode{true, false} {
		for _, icmpErr := range []icmpError{portUnreachable, timeToLiveExceeded} {
			wantErrno := wantErrno(connect, icmpErr)

			t.Run(fmt.Sprintf("%s/%s", connect, icmpErr), func(t *testing.T) {
				dut := testbench.NewDUT(t)

				remoteFD, remotePort := dut.CreateBoundSocket(t, unix.SOCK_DGRAM, unix.IPPROTO_UDP, net.IPv4zero)
				defer dut.Close(t, remoteFD)

				// Create a second, clean socket on the DUT to ensure that the ICMP
				// error messages only affect the sockets they are intended for.
				cleanFD, cleanPort := dut.CreateBoundSocket(t, unix.SOCK_DGRAM, unix.IPPROTO_UDP, net.IPv4zero)
				defer dut.Close(t, cleanFD)

				conn := dut.Net.NewUDPIPv4(t, testbench.UDP{DstPort: &remotePort}, testbench.UDP{SrcPort: &remotePort})
				defer conn.Close(t)

				if connect {
					dut.Connect(t, remoteFD, conn.LocalAddr(t))
					dut.Connect(t, cleanFD, conn.LocalAddr(t))
				}

				dut.SendTo(t, remoteFD, nil, 0, conn.LocalAddr(t))
				udp, err := conn.Expect(t, testbench.UDP{}, time.Second)
				if err != nil {
					t.Fatalf("did not receive message from DUT: %s", err)
				}

				var wg sync.WaitGroup
				wg.Add(2)
				go func() {
					defer wg.Done()

					if wantErrno != syscall.Errno(0) {
						ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
						defer cancel()

						ret, _, err := dut.RecvWithErrno(ctx, t, remoteFD, 100, 0)
						if ret != -1 {
							t.Errorf("recv during ICMP error succeeded unexpectedly, expected (%[1]d) %[1]v", wantErrno)
							return
						}
						if err != wantErrno {
							t.Errorf("recv during ICMP error resulted in error (%[1]d) %[1]v, expected (%[2]d) %[2]v", err, wantErrno)
							return
						}
					}

					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()

					if ret, _, err := dut.RecvWithErrno(ctx, t, remoteFD, 100, 0); ret == -1 {
						t.Errorf("recv after ICMP error failed with (%[1]d) %[1]", err)
					}
				}()

				go func() {
					defer wg.Done()

					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()

					if ret, _, err := dut.RecvWithErrno(ctx, t, cleanFD, 100, 0); ret == -1 {
						t.Errorf("recv on clean socket failed with (%[1]d) %[1]", err)
					}
				}()

				// TODO(b/155684889) This sleep is to allow time for the DUT to
				// actually call recv since we want the ICMP error to arrive during the
				// blocking recv, and should be replaced when a better synchronization
				// alternative is available.
				time.Sleep(2 * time.Second)

				sendICMPError(t, &conn, icmpErr, udp)

				conn.Send(t, testbench.UDP{DstPort: &cleanPort})
				conn.Send(t, testbench.UDP{})
				wg.Wait()
			})
		}
	}
}
