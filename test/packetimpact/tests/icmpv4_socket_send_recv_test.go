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

func TestICMPv4(t *testing.T) {
	runAllCombinations(t, &icmpV4Test{})
}

type icmpV4TestEnv struct {
	socketFD int32
	ident    uint16
	conn     testbench.IPv4Conn
	layers   testbench.Layers
}

type icmpV4Test struct{}

func (test *icmpV4Test) setup(t *testing.T, dut testbench.DUT, bindTo, sendTo net.IP, bindToDevice bool) icmpV4TestEnv {
	t.Helper()

	// Tell the DUT to create a socket.
	var socketFD int32
	var ident uint16

	if bindTo != nil {
		socketFD, ident = dut.CreateBoundSocket(t, unix.SOCK_DGRAM, unix.IPPROTO_ICMP, bindTo)
	} else {
		// An unbound socket will auto-bind to INADDR_ANY.
		socketFD = dut.Socket(t, unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_ICMP)
	}
	t.Cleanup(func() {
		dut.Close(t, socketFD)
	})

	if bindToDevice {
		dut.SetSockOpt(t, socketFD, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, []byte(dut.Net.RemoteDevName))
	}

	// Create a socket on the test runner.
	conn := dut.Net.NewIPv4Conn(t, testbench.IPv4{}, testbench.IPv4{})
	t.Cleanup(func() {
		conn.Close(t)
	})

	dstAddr := sendTo.To4()
	return icmpV4TestEnv{
		socketFD: socketFD,
		ident:    ident,
		conn:     conn,
		layers: testbench.Layers{
			expectedEthLayer(t, dut, socketFD, sendTo),
			&testbench.IPv4{
				DstAddr: &dstAddr,
			},
		},
	}
}

func (test *icmpV4Test) Send(t *testing.T, dut testbench.DUT, bindTo, sendTo net.IP, bindToDevice bool) {
	if bindTo.To4() == nil || isBroadcastOrMulticast(dut, bindTo) {
		// ICMPv4 sockets cannot bind to IPv6, broadcast, or multicast
		// addresses.
		return
	}

	isV4 := sendTo.To4() != nil

	// TODO(gvisor.dev/issue/5681): Remove this case once ICMP sockets allow
	// sending to broadcast and multicast addresses.
	if (dut.Uname.IsGvisor() || dut.Uname.IsFuchsia()) && isV4 && isBroadcastOrMulticast(dut, sendTo) {
		// expectPacket cannot be false. In some cases the packet will send, but
		// with IPv4 destination incorrectly set to RemoteIPv4. It's all bad and
		// not worth the effort to create a special case when this occurs.
		t.Skip("TODO(gvisor.dev/issue/5681): Allow sending to broadcast and multicast addresses with ICMP sockets.")
	}

	expectNetworkUnreachable := true
	// We don't expect ENETUNREACH if any of the follwing is true:
	// 1. bindTo is specfied.
	if !bindTo.Equal(net.IPv4zero) {
		expectNetworkUnreachable = false
	}
	// 2. We are binding to a device.
	if bindToDevice {
		expectNetworkUnreachable = false
	}
	// 3. sendTo is neither 224.0.0.1 nor 255.255.255.255.
	if !sendTo.Equal(net.IPv4bcast) && !sendTo.Equal(net.IPv4allsys) {
		expectNetworkUnreachable = false
	}

	expectPacket := true
	// We don't expect an incoming packet if any of the following is true:
	// 1. sendTo is not an ipv4 address.
	if !isV4 {
		expectPacket = false
	}
	// 2. sendTo is the dut itself.
	if sendTo.Equal(dut.Net.RemoteIPv4) {
		expectPacket = false
	}
	// 3. we are expecting ENETUNREACH.
	if expectNetworkUnreachable {
		expectPacket = false
	}

	env := test.setup(t, dut, bindTo, sendTo, bindToDevice)

	for name, payload := range map[string][]byte{
		"empty":    nil,
		"small":    []byte("hello world"),
		"random1k": testbench.GenerateRandomPayload(t, maxICMPv4PayloadSize),
	} {
		t.Run(name, func(t *testing.T) {
			icmpLayer := &testbench.ICMPv4{
				Type:    testbench.ICMPv4Type(header.ICMPv4Echo),
				Payload: payload,
			}
			bytes, err := icmpLayer.ToBytes()
			if err != nil {
				t.Fatalf("icmpLayer.ToBytes() = %s", err)
			}
			destSockaddr := unix.SockaddrInet4{}
			copy(destSockaddr.Addr[:], sendTo.To4())

			// Tell the DUT to send a packet out the ICMP socket.
			ret, err := dut.SendToWithErrno(context.Background(), t, env.socketFD, bytes, 0, &destSockaddr)
			if expectNetworkUnreachable {
				if !(ret == -1 && err == unix.ENETUNREACH) {
					t.Fatalf("got dut.SendToWithErrno = (%d, %s), want (-1, %s)", ret, err, unix.ENETUNREACH)
				}
			} else {
				if !(int(ret) == len(bytes) && err == unix.Errno(0)) {
					t.Fatalf("got dut.SendToWithErrno = (%d, %s), want (%d, 0)", ret, err, len(bytes))
				}
			}

			// Verify the test runner received an ICMP packet with the correctly
			// set "ident".
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

func (test *icmpV4Test) Receive(t *testing.T, dut testbench.DUT, bindTo, sendTo net.IP, bindToDevice bool) {
	if bindTo.To4() == nil || isBroadcastOrMulticast(dut, bindTo) {
		// ICMPv4 sockets cannot bind to IPv6, broadcast, or multicast
		// addresses.
		return
	}

	expectPacket := (bindTo.Equal(dut.Net.RemoteIPv4) || bindTo.Equal(net.IPv4zero)) && sendTo.Equal(dut.Net.RemoteIPv4)

	// TODO(gvisor.dev/issue/5763): Remove this if statement once gVisor
	// restricts ICMP sockets to receive only from unicast addresses.
	if (dut.Uname.IsGvisor() || dut.Uname.IsFuchsia()) && bindTo.Equal(net.IPv4zero) && isBroadcastOrMulticast(dut, sendTo) {
		expectPacket = true
	}

	env := test.setup(t, dut, bindTo, sendTo, bindToDevice)

	for name, payload := range map[string][]byte{
		"empty":    nil,
		"small":    []byte("hello world"),
		"random1k": testbench.GenerateRandomPayload(t, maxICMPv4PayloadSize),
	} {
		t.Run(name, func(t *testing.T) {
			icmpLayer := &testbench.ICMPv4{
				Type:    testbench.ICMPv4Type(header.ICMPv4EchoReply),
				Payload: payload,
			}
			if env.ident != 0 {
				icmpLayer.Ident = &env.ident
			}

			// Send an ICMPv4 packet from the test runner to the DUT.
			frame := env.conn.CreateFrame(t, env.layers, icmpLayer)
			env.conn.SendFrame(t, frame)

			// Verify the behavior of the ICMP socket on the DUT.
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
				ret, recvPayload, errno := dut.RecvWithErrno(context.Background(), t, env.socketFD, maxICMPv4PayloadSize, 0)
				if errno != unix.EAGAIN || errno != unix.EWOULDBLOCK {
					t.Errorf("Recv got unexpected result, ret=%d, payload=%q, errno=%s", ret, recvPayload, errno)
				}
			}
		})
	}
}
