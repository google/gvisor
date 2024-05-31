// Copyright 2021 The gVisor Authors.
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

package generic_dgram_socket_send_recv_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

func TestICMPv6(t *testing.T) {
	runAllCombinations(t, &icmpV6Test{})
}

type icmpV6TestEnv struct {
	socketFD int32
	ident    uint16
	conn     testbench.IPv6Conn
	layers   testbench.Layers
}

// icmpV6Test and icmpV4Test look substantially similar at first look, but have
// enough subtle differences in setup and test expectations to discourage
// refactoring:
//   - Different IP layers
//   - Different testbench.Connections
//   - Different UNIX domain and proto arguments
//   - Different expectPacket and wantErrno for send and receive
type icmpV6Test struct{}

func (test *icmpV6Test) setup(t *testing.T, dut testbench.DUT, bindTo, sendTo net.IP, bindToDevice bool) icmpV6TestEnv {
	t.Helper()

	// Tell the DUT to create a socket.
	var socketFD int32
	var ident uint16

	if bindTo != nil {
		socketFD, ident = dut.CreateBoundSocket(t, unix.SOCK_DGRAM, unix.IPPROTO_ICMPV6, bindTo)
	} else {
		// An unbound socket will auto-bind to IN6ADDR_ANY_INIT.
		socketFD = dut.Socket(t, unix.AF_INET6, unix.SOCK_DGRAM, unix.IPPROTO_ICMPV6)
	}
	t.Cleanup(func() {
		dut.Close(t, socketFD)
	})

	if bindToDevice {
		dut.SetSockOpt(t, socketFD, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, []byte(dut.Net.RemoteDevName))
	}

	// Create a socket on the test runner.
	conn := dut.Net.NewIPv6Conn(t, testbench.IPv6{}, testbench.IPv6{})
	t.Cleanup(func() {
		conn.Close(t)
	})

	dstAddr := sendTo.To16()
	return icmpV6TestEnv{
		socketFD: socketFD,
		ident:    ident,
		conn:     conn,
		layers: testbench.Layers{
			expectedEthLayer(t, dut, socketFD, sendTo),
			&testbench.IPv6{
				DstAddr: &dstAddr,
			},
		},
	}
}

func (test *icmpV6Test) Send(t *testing.T, dut testbench.DUT, bindTo, sendTo net.IP, bindToDevice bool) {
	if bindTo.To4() != nil || bindTo.IsMulticast() {
		// ICMPv6 sockets cannot bind to IPv4 or multicast addresses.
		return
	}

	expectPacket := sendTo.Equal(dut.Net.LocalIPv6)
	wantErrno := unix.Errno(0)

	if sendTo.To4() != nil {
		wantErrno = unix.EINVAL

		// TODO(gvisor.dev/issue/5966): Remove this if statement once ICMPv6 sockets
		// return EINVAL after calling sendto with an IPv4 address.
		if dut.Uname.IsGvisor() || dut.Uname.IsFuchsia() {
			wantErrno = unix.ENETUNREACH
			if !bindTo.Equal(dut.Net.RemoteIPv6) && (bindToDevice || isInTestSubnetV4(dut, sendTo)) {
				wantErrno = unix.Errno(0)
			}
		}
	}

	env := test.setup(t, dut, bindTo, sendTo, bindToDevice)

	for name, payload := range map[string][]byte{
		"empty":    nil,
		"small":    []byte("hello world"),
		"random1k": testbench.GenerateRandomPayload(t, maxICMPv6PayloadSize),
	} {
		t.Run(name, func(t *testing.T) {
			icmpLayer := &testbench.ICMPv6{
				Type:    testbench.ICMPv6Type(header.ICMPv6EchoRequest),
				Payload: payload,
			}
			bytes, err := icmpLayer.ToBytes()
			if err != nil {
				t.Fatalf("icmpLayer.ToBytes() = %s", err)
			}
			destSockaddr := unix.SockaddrInet6{
				ZoneId: dut.Net.RemoteDevID,
			}
			copy(destSockaddr.Addr[:], sendTo.To16())

			// Tell the DUT to send a packet out the ICMPv6 socket.
			gotRet, gotErrno := dut.SendToWithErrno(context.Background(), t, env.socketFD, bytes, 0, &destSockaddr)

			if gotErrno != wantErrno {
				t.Fatalf("got dut.SendToWithErrno(_, _, %d, _, _, %s) = (_, %s), want = (_, %s)", env.socketFD, sendTo, gotErrno, wantErrno)
			}
			if wantErrno != 0 {
				return
			}
			if got, want := int(gotRet), len(bytes); got != want {
				t.Fatalf("got dut.SendToWithErrno(_, _, %d, _, _, %s) = (%d, _), want = (%d, _)", env.socketFD, sendTo, got, want)
			}

			// Verify the test runner received an ICMPv6 packet with the
			// correctly set "ident".
			if env.ident != 0 {
				icmpLayer.Ident = &env.ident
			}
			want := append(env.layers, icmpLayer)
			if got, ok := env.conn.ListenForFrame(t, want, time.Second); !ok && expectPacket {
				t.Fatalf("did not receive expected frame matching %s\nGot frames: %s", want, got)
			} else if ok && !expectPacket {
				matchedFrame := got[len(got)-1]
				t.Fatalf("got unexpected frame matching %s\nGot frame: %s", want, matchedFrame)
			}
		})
	}
}

func (test *icmpV6Test) Receive(t *testing.T, dut testbench.DUT, bindTo, sendTo net.IP, bindToDevice bool) {
	if bindTo.To4() != nil || bindTo.IsMulticast() {
		// ICMPv6 sockets cannot bind to IPv4 or multicast addresses.
		return
	}

	expectPacket := true
	switch {
	case bindTo.Equal(dut.Net.RemoteIPv6) && sendTo.Equal(dut.Net.RemoteIPv6):
	case bindTo.Equal(net.IPv6zero) && sendTo.Equal(dut.Net.RemoteIPv6):
	case bindTo.Equal(net.IPv6zero) && sendTo.Equal(net.IPv6linklocalallnodes):
	default:
		expectPacket = false
	}

	// TODO(gvisor.dev/issue/5763): Remove this if statement once gVisor
	// restricts ICMP sockets to receive only from unicast addresses.
	if (dut.Uname.IsGvisor() || dut.Uname.IsFuchsia()) && bindTo.Equal(net.IPv6zero) && isBroadcastOrMulticast(dut, sendTo) {
		expectPacket = false
	}

	env := test.setup(t, dut, bindTo, sendTo, bindToDevice)

	for name, payload := range map[string][]byte{
		"empty":    nil,
		"small":    []byte("hello world"),
		"random1k": testbench.GenerateRandomPayload(t, maxICMPv6PayloadSize),
	} {
		t.Run(name, func(t *testing.T) {
			icmpLayer := &testbench.ICMPv6{
				Type:    testbench.ICMPv6Type(header.ICMPv6EchoReply),
				Payload: payload,
			}
			if env.ident != 0 {
				icmpLayer.Ident = &env.ident
			}

			// Send an ICMPv6 packet from the test runner to the DUT.
			frame := env.conn.CreateFrame(t, env.layers, icmpLayer)
			env.conn.SendFrame(t, frame)

			// Verify the behavior of the ICMPv6 socket on the DUT.
			if expectPacket {
				payload, err := icmpLayer.ToBytes()
				if err != nil {
					t.Fatalf("icmpLayer.ToBytes() = %s", err)
				}

				// Receive one extra byte to assert the length of the
				// packet received in the case where the packet contains
				// more data than expected.
				len := int32(len(payload)) + 1
				got, want := dut.Recv(t, env.socketFD, len, 0), payload
				if diff := cmp.Diff(want, got); diff != "" {
					t.Errorf("received payload does not match sent payload, diff (-want, +got):\n%s", diff)
				}
			} else {
				// Expected receive error, set a short receive timeout.
				dut.SetSockOptTimeval(
					t,
					env.socketFD,
					unix.SOL_SOCKET,
					unix.SO_RCVTIMEO,
					&unix.Timeval{
						Sec:  1,
						Usec: 0,
					},
				)
				ret, recvPayload, errno := dut.RecvWithErrno(context.Background(), t, env.socketFD, maxICMPv6PayloadSize, 0)
				if errno != unix.EAGAIN || errno != unix.EWOULDBLOCK {
					t.Errorf("Recv got unexpected result, ret=%d, payload=%q, errno=%s", ret, recvPayload, errno)
				}
			}
		})
	}
}
