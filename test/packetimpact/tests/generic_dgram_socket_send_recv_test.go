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
	"flag"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

const (
	// Even though sockets allow larger datagrams we don't test it here as they
	// need to be fragmented and written out as individual frames.

	maxICMPv4PayloadSize = header.IPv4MinimumMTU - header.EthernetMinimumSize - header.IPv4MinimumSize - header.ICMPv4MinimumSize
	maxICMPv6PayloadSize = header.IPv6MinimumMTU - header.EthernetMinimumSize - header.IPv6MinimumSize - header.ICMPv6MinimumSize
	maxUDPv4PayloadSize  = header.IPv4MinimumMTU - header.EthernetMinimumSize - header.IPv4MinimumSize - header.UDPMinimumSize
	maxUDPv6PayloadSize  = header.IPv6MinimumMTU - header.EthernetMinimumSize - header.IPv6MinimumSize - header.UDPMinimumSize
)

func maxUDPPayloadSize(addr net.IP) int {
	if addr.To4() != nil {
		return maxUDPv4PayloadSize
	}
	return maxUDPv6PayloadSize
}

func init() {
	testbench.Initialize(flag.CommandLine)
	testbench.RPCTimeout = 500 * time.Millisecond
}

func expectedEthLayer(t *testing.T, dut testbench.DUT, socketFD int32, sendTo net.IP) testbench.Layer {
	t.Helper()
	dst := func() tcpip.LinkAddress {
		if isBroadcast(dut, sendTo) {
			dut.SetSockOptInt(t, socketFD, unix.SOL_SOCKET, unix.SO_BROADCAST, 1)

			// When sending to broadcast (subnet or limited), the expected ethernet
			// address is also broadcast.
			return header.EthernetBroadcastAddress
		}
		if sendTo.IsMulticast() {
			if sendTo4 := sendTo.To4(); sendTo4 != nil {
				return header.EthernetAddressFromMulticastIPv4Address(tcpip.Address(sendTo4))
			}
			return header.EthernetAddressFromMulticastIPv6Address(tcpip.Address(sendTo.To16()))
		}
		return ""
	}()
	var ether testbench.Ether
	if len(dst) != 0 {
		ether.DstAddr = &dst
	}
	return &ether
}

type protocolTest interface {
	Name() string
	Send(t *testing.T, dut testbench.DUT, bindTo, sendTo net.IP, bindToDevice bool)
	Receive(t *testing.T, dut testbench.DUT, bindTo, sendTo net.IP, bindToDevice bool)
}

func TestSocket(t *testing.T) {
	dut := testbench.NewDUT(t)
	subnetBroadcast := dut.Net.SubnetBroadcast()

	for _, proto := range []protocolTest{
		&icmpV4Test{},
		&icmpV6Test{},
		&udpTest{},
	} {
		t.Run(proto.Name(), func(t *testing.T) {
			// Test every combination of bound/unbound, broadcast/multicast/unicast
			// bound/destination address, and bound/not-bound to device.
			for _, bindTo := range []net.IP{
				nil, // Do not bind.
				net.IPv4zero,
				net.IPv4bcast,
				net.IPv4allsys,
				net.IPv6zero,
				subnetBroadcast,
				dut.Net.RemoteIPv4,
				dut.Net.RemoteIPv6,
			} {
				t.Run(fmt.Sprintf("bindTo=%s", bindTo), func(t *testing.T) {
					for _, sendTo := range []net.IP{
						net.IPv4bcast,
						net.IPv4allsys,
						subnetBroadcast,
						dut.Net.LocalIPv4,
						dut.Net.LocalIPv6,
						dut.Net.RemoteIPv4,
						dut.Net.RemoteIPv6,
					} {
						t.Run(fmt.Sprintf("sendTo=%s", sendTo), func(t *testing.T) {
							for _, bindToDevice := range []bool{true, false} {
								t.Run(fmt.Sprintf("bindToDevice=%t", bindToDevice), func(t *testing.T) {
									t.Run("Send", func(t *testing.T) {
										proto.Send(t, dut, bindTo, sendTo, bindToDevice)
									})
									t.Run("Receive", func(t *testing.T) {
										proto.Receive(t, dut, bindTo, sendTo, bindToDevice)
									})
								})
							}
						})
					}
				})
			}
		})
	}
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

	return icmpV4TestEnv{
		socketFD: socketFD,
		ident:    ident,
		conn:     conn,
		layers: testbench.Layers{
			expectedEthLayer(t, dut, socketFD, sendTo),
			&testbench.IPv4{
				DstAddr: testbench.Address(tcpip.Address(sendTo.To4())),
			},
		},
	}
}

var _ protocolTest = (*icmpV4Test)(nil)

func (*icmpV4Test) Name() string { return "icmpv4" }

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

	expectPacket := isV4 && !sendTo.Equal(dut.Net.RemoteIPv4)
	switch {
	case bindTo.Equal(dut.Net.RemoteIPv4):
		// If we're explicitly bound to an interface's unicast address,
		// packets are always sent on that interface.
	case bindToDevice:
		// If we're explicitly bound to an interface, packets are always
		// sent on that interface.
	case !sendTo.Equal(net.IPv4bcast) && !sendTo.IsMulticast():
		// If we're not sending to limited broadcast or multicast, the route
		// table will be consulted and packets will be sent on the correct
		// interface.
	default:
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
			if got, want := dut.SendTo(t, env.socketFD, bytes, 0, &destSockaddr), len(bytes); int(got) != want {
				t.Fatalf("got dut.SendTo = %d, want %d", got, want)
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

type icmpV6TestEnv struct {
	socketFD int32
	ident    uint16
	conn     testbench.IPv6Conn
	layers   testbench.Layers
}

// icmpV6Test and icmpV4Test look substantially similar at first look, but have
// enough subtle differences in setup and test expectations to discourage
// refactoring:
//  - Different IP layers
//  - Different testbench.Connections
//  - Different UNIX domain and proto arguments
//  - Different expectPacket and wantErrno for send and receive
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

	return icmpV6TestEnv{
		socketFD: socketFD,
		ident:    ident,
		conn:     conn,
		layers: testbench.Layers{
			expectedEthLayer(t, dut, socketFD, sendTo),
			&testbench.IPv6{
				DstAddr: testbench.Address(tcpip.Address(sendTo.To16())),
			},
		},
	}
}

var _ protocolTest = (*icmpV6Test)(nil)

func (*icmpV6Test) Name() string { return "icmpv6" }

func (test *icmpV6Test) Send(t *testing.T, dut testbench.DUT, bindTo, sendTo net.IP, bindToDevice bool) {
	if bindTo.To4() != nil || bindTo.IsMulticast() {
		// ICMPv6 sockets cannot bind to IPv4 or multicast addresses.
		return
	}

	expectPacket := sendTo.Equal(dut.Net.LocalIPv6)
	wantErrno := unix.Errno(0)

	if sendTo.To4() != nil {
		wantErrno = unix.EINVAL
	}

	// TODO(gvisor.dev/issue/5966): Remove this if statement once ICMPv6 sockets
	// return EINVAL after calling sendto with an IPv4 address.
	if (dut.Uname.IsGvisor() || dut.Uname.IsFuchsia()) && sendTo.To4() != nil {
		switch {
		case bindTo.Equal(dut.Net.RemoteIPv6):
			wantErrno = unix.ENETUNREACH
		case bindTo.Equal(net.IPv6zero) || bindTo == nil:
			wantErrno = unix.Errno(0)
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
			ctx, cancel := context.WithTimeout(context.Background(), testbench.RPCTimeout)
			defer cancel()
			gotRet, gotErrno := dut.SendToWithErrno(ctx, t, env.socketFD, bytes, 0, &destSockaddr)

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

type udpConn interface {
	SrcPort(*testing.T) uint16
	SendFrame(*testing.T, testbench.Layers, ...testbench.Layer)
	ListenForFrame(*testing.T, testbench.Layers, time.Duration) ([]testbench.Layers, bool)
	Close(*testing.T)
}

type udpTestEnv struct {
	socketFD int32
	conn     udpConn
	layers   testbench.Layers
}

type udpTest struct{}

func (test *udpTest) setup(t *testing.T, dut testbench.DUT, bindTo, sendTo net.IP, bindToDevice bool) udpTestEnv {
	t.Helper()

	var (
		socketFD                 int32
		outgoingUDP, incomingUDP testbench.UDP
	)

	// Tell the DUT to create a socket.
	if bindTo != nil {
		var remotePort uint16
		socketFD, remotePort = dut.CreateBoundSocket(t, unix.SOCK_DGRAM, unix.IPPROTO_UDP, bindTo)
		outgoingUDP.DstPort = &remotePort
		incomingUDP.SrcPort = &remotePort
	} else {
		// An unbound socket will auto-bind to INADDR_ANY.
		socketFD = dut.Socket(t, unix.AF_INET6, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
	}
	t.Cleanup(func() {
		dut.Close(t, socketFD)
	})

	if bindToDevice {
		dut.SetSockOpt(t, socketFD, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, []byte(dut.Net.RemoteDevName))
	}

	// Create a socket on the test runner.
	var conn udpConn
	var ipLayer testbench.Layer
	if addr := sendTo.To4(); addr != nil {
		udpConn := dut.Net.NewUDPIPv4(t, outgoingUDP, incomingUDP)
		conn = &udpConn
		ipLayer = &testbench.IPv4{
			DstAddr: testbench.Address(tcpip.Address(addr)),
		}
	} else {
		udpConn := dut.Net.NewUDPIPv6(t, outgoingUDP, incomingUDP)
		conn = &udpConn
		ipLayer = &testbench.IPv6{
			DstAddr: testbench.Address(tcpip.Address(sendTo.To16())),
		}
	}
	t.Cleanup(func() {
		conn.Close(t)
	})

	return udpTestEnv{
		socketFD: socketFD,
		conn:     conn,
		layers: testbench.Layers{
			expectedEthLayer(t, dut, socketFD, sendTo),
			ipLayer,
			&incomingUDP,
		},
	}
}

var _ protocolTest = (*udpTest)(nil)

func (*udpTest) Name() string { return "udp" }

func (test *udpTest) Send(t *testing.T, dut testbench.DUT, bindTo, sendTo net.IP, bindToDevice bool) {
	canSend := bindTo == nil || bindTo.Equal(net.IPv6zero) || sameIPVersion(sendTo, bindTo)
	expectPacket := canSend && !isRemoteAddr(dut, sendTo)
	switch {
	case bindTo.Equal(dut.Net.RemoteIPv4):
		// If we're explicitly bound to an interface's unicast address,
		// packets are always sent on that interface.
	case bindToDevice:
		// If we're explicitly bound to an interface, packets are always
		// sent on that interface.
	case !sendTo.Equal(net.IPv4bcast) && !sendTo.IsMulticast():
		// If we're not sending to limited broadcast, multicast, or local, the
		// route table will be consulted and packets will be sent on the correct
		// interface.
	default:
		expectPacket = false
	}

	wantErrno := unix.Errno(0)
	switch {
	case !canSend && bindTo.To4() != nil:
		wantErrno = unix.EAFNOSUPPORT
	case !canSend && bindTo.To4() == nil:
		wantErrno = unix.ENETUNREACH
	}

	// TODO(gvisor.dev/issue/5967): Remove this if statement once UDPv4 sockets
	// returns EAFNOSUPPORT after calling sendto with an IPv6 address.
	if dut.Uname.IsGvisor() && !canSend && bindTo.To4() != nil {
		wantErrno = unix.EINVAL
	}

	// TODO(https://fxbug.dev/78430): Remove this if statement once UDP
	// sockets on Fuchsia disallow sending to IPv4 broadcast and multicast
	// when bound to IPv6 any.
	if dut.Uname.IsFuchsia() && bindTo.Equal(net.IPv6zero) && (sendTo.Equal(net.IPv4bcast) || sendTo.Equal(net.IPv4allsys)) && !bindToDevice {
		expectPacket = true
	}

	env := test.setup(t, dut, bindTo, sendTo, bindToDevice)

	for name, payload := range map[string][]byte{
		"empty":    nil,
		"small":    []byte("hello world"),
		"random1k": testbench.GenerateRandomPayload(t, maxUDPPayloadSize(bindTo)),
	} {
		t.Run(name, func(t *testing.T) {
			var destSockaddr unix.Sockaddr
			if sendTo4 := sendTo.To4(); sendTo4 != nil {
				addr := unix.SockaddrInet4{
					Port: int(env.conn.SrcPort(t)),
				}
				copy(addr.Addr[:], sendTo4)
				destSockaddr = &addr
			} else {
				addr := unix.SockaddrInet6{
					Port:   int(env.conn.SrcPort(t)),
					ZoneId: dut.Net.RemoteDevID,
				}
				copy(addr.Addr[:], sendTo.To16())
				destSockaddr = &addr
			}

			// Tell the DUT to send a packet out the UDP socket.
			ctx, cancel := context.WithTimeout(context.Background(), testbench.RPCTimeout)
			defer cancel()
			gotRet, gotErrno := dut.SendToWithErrno(ctx, t, env.socketFD, payload, 0, destSockaddr)

			if gotErrno != wantErrno {
				t.Fatalf("got dut.SendToWithErrno(_, _, %d, _, _, %s) = (_, %s), want = (_, %s)", env.socketFD, sendTo, gotErrno, wantErrno)
			}
			if wantErrno != 0 {
				return
			}
			if got, want := int(gotRet), len(payload); got != want {
				t.Fatalf("got dut.SendToWithErrno(_, _, %d, _, _, %s) = (%d, _), want = (%d, _)", env.socketFD, sendTo, got, want)
			}

			// Verify the test runner received a UDP packet with the
			// correct payload.
			want := append(env.layers, &testbench.Payload{
				Bytes: payload,
			})
			if got, ok := env.conn.ListenForFrame(t, want, time.Second); !ok && expectPacket {
				t.Fatalf("did not receive expected frame matching %s\nGot frames: %s", want, got)
			} else if ok && !expectPacket {
				matchedFrame := got[len(got)-1]
				t.Fatalf("got unexpected frame matching %s\nGot frame: %s", want, matchedFrame)
			}
		})
	}
}

func (test *udpTest) Receive(t *testing.T, dut testbench.DUT, bindTo, sendTo net.IP, bindToDevice bool) {
	subnetBroadcast := dut.Net.SubnetBroadcast()

	expectPacket := true
	switch {
	case bindTo.Equal(sendTo):
	case bindTo.Equal(net.IPv4zero) && sameIPVersion(bindTo, sendTo) && !sendTo.Equal(dut.Net.LocalIPv4):
	case bindTo.Equal(net.IPv6zero) && isBroadcast(dut, sendTo):
	case bindTo.Equal(net.IPv6zero) && isRemoteAddr(dut, sendTo):
	case bindTo.Equal(subnetBroadcast) && sendTo.Equal(subnetBroadcast):
	default:
		expectPacket = false
	}

	// TODO(gvisor.dev/issue/5956): Remove this if statement once gVisor
	// restricts ICMP sockets to receive only from unicast addresses.
	if (dut.Uname.IsGvisor() || dut.Uname.IsFuchsia()) && bindTo.Equal(net.IPv6zero) && sendTo.Equal(net.IPv4allsys) {
		expectPacket = true
	}

	env := test.setup(t, dut, bindTo, sendTo, bindToDevice)
	maxPayloadSize := maxUDPPayloadSize(bindTo)

	for name, payload := range map[string][]byte{
		"empty":    nil,
		"small":    []byte("hello world"),
		"random1k": testbench.GenerateRandomPayload(t, maxPayloadSize),
	} {
		t.Run(name, func(t *testing.T) {
			// Send a UDP packet from the test runner to the DUT.
			env.conn.SendFrame(t, env.layers, &testbench.Payload{Bytes: payload})

			// Verify the behavior of the ICMP socket on the DUT.
			if expectPacket {
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
				ret, recvPayload, errno := dut.RecvWithErrno(context.Background(), t, env.socketFD, int32(maxPayloadSize), 0)
				if errno != unix.EAGAIN || errno != unix.EWOULDBLOCK {
					t.Errorf("Recv got unexpected result, ret=%d, payload=%q, errno=%s", ret, recvPayload, errno)
				}
			}
		})
	}
}

func isBroadcast(dut testbench.DUT, ip net.IP) bool {
	return ip.Equal(net.IPv4bcast) || ip.Equal(dut.Net.SubnetBroadcast())
}

func isBroadcastOrMulticast(dut testbench.DUT, ip net.IP) bool {
	return isBroadcast(dut, ip) || ip.IsMulticast()
}

func sameIPVersion(a, b net.IP) bool {
	return (a.To4() == nil) == (b.To4() == nil)
}

func isRemoteAddr(dut testbench.DUT, ip net.IP) bool {
	return ip.Equal(dut.Net.RemoteIPv4) || ip.Equal(dut.Net.RemoteIPv6)
}
