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

package sendmsg_recvmsg_test

import (
	"flag"
	"net"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

func init() {
	testbench.RegisterFlags(flag.CommandLine)
}

// TestSendmsgIPv4 is a basic test which tests the sendmsg syscall
// functionality using a UDP/IPv4 socket.
func TestSendmsgIPv4(t *testing.T) {
	dut := testbench.NewDUT(t)
	defer dut.TearDown()

	remoteFD, remotePort := dut.CreateBoundSocket(unix.SOCK_DGRAM, unix.IPPROTO_UDP, net.ParseIP("0.0.0.0").To4())
	defer dut.Close(remoteFD)

	conn := testbench.NewUDPIPv4(t, testbench.UDP{DstPort: &remotePort}, testbench.UDP{SrcPort: &remotePort})
	defer conn.Close()

	ttl := uint8(dut.GetSockOptInt(remoteFD, unix.IPPROTO_IP, unix.IP_TTL))
	if ttl <= 1 {
		ttl = 255
	} else {
		ttl--
	}

	var sendCMsg testbench.CMsg
	sendCMsg.SetTTL(ttl)

	socketTOS := uint8(dut.GetSockOptInt(remoteFD, unix.IPPROTO_IP, unix.IP_TOS))
	tos := socketTOS | 0xC
	if socketTOS == tos {
		t.Fatalf("got UDP datagram with IPv4 TOS=%d, want the 2 least-significant bits of DSCP to not be 0b11", socketTOS)
	}
	sendCMsg.SetTOS(tos)

	// TODO(b/158321196) This is mostly a noop right now since it doesn't
	// cause the packet to be sent to have a different source address. If
	// multiple addresses are configured then this can actually affect the
	// source address on the packet.
	sendCMsg.SetPacketInfo(0, testbench.Address(tcpip.Address(net.ParseIP(testbench.RemoteIPv4).To4())))

	payload := []byte("sample data")
	dut.SendMsg(remoteFD, conn.LocalAddr(), [][]byte{payload}, &sendCMsg, 0)
	layers, err := conn.ExpectData(testbench.UDP{}, testbench.Payload{Bytes: payload}, time.Second)
	if err != nil {
		t.Fatalf("failed to receive UDP datagram sent with sendmsg: %s", err)
	}

	ip, ok := layers[1].(*testbench.IPv4)
	if !ok {
		t.Fatalf("got network layer header of type: %T, expected: *IPv4", layers[1])
	}
	if *ip.TOS != tos {
		t.Fatalf("got IPv4 TOS=%d, want %d", *ip.TOS, tos)
	}
	if *ip.TTL != ttl {
		t.Fatalf("got IPv4 TTL=%d, want %d", *ip.TTL, ttl)
	}
}

func TestRecvmsgIPv4(t *testing.T) {
	dut := testbench.NewDUT(t)
	defer dut.TearDown()

	remoteFD, remotePort := dut.CreateBoundSocket(unix.SOCK_DGRAM, unix.IPPROTO_UDP, net.ParseIP("0.0.0.0").To4())
	defer dut.Close(remoteFD)

	conn := testbench.NewUDPIPv4(t, testbench.UDP{DstPort: &remotePort}, testbench.UDP{SrcPort: &remotePort})
	defer conn.Close()

	dut.SetSockOptInt(remoteFD, unix.IPPROTO_IP, unix.IP_RECVORIGDSTADDR, 1)
	dut.SetSockOptInt(remoteFD, unix.IPPROTO_IP, unix.IP_PKTINFO, 1)
	dut.SetSockOptInt(remoteFD, unix.IPPROTO_IP, unix.IP_RECVTOS, 1)
	dut.SetSockOptInt(remoteFD, unix.IPPROTO_IP, unix.IP_RECVTTL, 1)

	payload := []byte("sample data")
	wantTTL := uint8(255)
	wantTOS := uint8(0xC)
	conn.SendIP(testbench.IPv4{TOS: &wantTOS, TTL: &wantTTL}, testbench.UDP{}, &testbench.Payload{Bytes: payload})
	srcAddr, iov, cmsg, _ := dut.RecvMsg(remoteFD, []int32{2048}, 4096, 0)

	if !testbench.SockaddrEqual(srcAddr, conn.LocalAddr()) {
		t.Fatalf("got source address: %+v, want: %+v", srcAddr, conn.LocalAddr())
	}
	if len(iov) == 0 || string(iov[0]) != string(payload) {
		t.Fatalf("got iovec: %v, want one buffer with payload: %s", iov, string(payload))
	}

	remoteAddr := tcpip.Address(net.ParseIP(testbench.RemoteIPv4).To4())

	_, specDstAddr, addr, err := cmsg.IPPktInfo()
	if err != nil {
		t.Fatal(err)
	}
	if *specDstAddr != remoteAddr {
		t.Fatalf("got IP_PKTINFO specDstAddr: %v, want: %v", *specDstAddr, remoteAddr)
	}
	if *addr != remoteAddr {
		t.Fatalf("got IP_PKTINFO destination addr: %v, want: %v", *addr, remoteAddr)
	}

	remoteSockaddr := &unix.SockaddrInet4{Port: int(remotePort)}
	copy(remoteSockaddr.Addr[:], remoteAddr)
	origDstAddr, err := cmsg.OrigDstAddr()
	if err != nil {
		t.Fatal(err)
	}
	if *origDstAddr != *remoteSockaddr {
		t.Fatalf("got IP_ORIGDSTADDR: %v, want: %v", *origDstAddr, *remoteSockaddr)
	}

	ttl, err := cmsg.TTL()
	if err != nil {
		t.Fatal(err)
	}
	if ttl != wantTTL {
		t.Fatalf("got IP_TTL TTL=%d, want %d", ttl, wantTTL)
	}

	tos, err := cmsg.TOS()
	if err != nil {
		t.Fatal(err)
	}
	if tos != wantTOS {
		t.Fatalf("got IP_TOS TOS=%d, want %d", tos, wantTOS)
	}
}
