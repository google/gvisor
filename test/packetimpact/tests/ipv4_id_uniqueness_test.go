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

package ipv4_id_uniqueness_test

import (
	"context"
	"flag"
	"fmt"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

func init() {
	testbench.Initialize(flag.CommandLine)
}

func recvTCPSegment(t *testing.T, conn *testbench.TCPIPv4, expect *testbench.TCP, expectPayload *testbench.Payload) (uint16, error) {
	layers, err := conn.ExpectData(t, expect, expectPayload, time.Second)
	if err != nil {
		return 0, fmt.Errorf("failed to receive TCP segment: %s", err)
	}
	if len(layers) < 2 {
		return 0, fmt.Errorf("got packet with layers: %v, expected to have at least 2 layers (link and network)", layers)
	}
	ipv4, ok := layers[1].(*testbench.IPv4)
	if !ok {
		return 0, fmt.Errorf("got network layer: %T, expected: *IPv4", layers[1])
	}
	if *ipv4.Flags&header.IPv4FlagDontFragment != 0 {
		return 0, fmt.Errorf("got IPv4 DF=1, expected DF=0")
	}
	return *ipv4.ID, nil
}

// RFC 6864 section 4.2 states: "The IPv4 ID of non-atomic datagrams MUST NOT
// be reused when sending a copy of an earlier non-atomic datagram."
//
// This test creates a TCP connection, uses the IP_MTU_DISCOVER socket option
// to force the DF bit to be 0, and checks that a retransmitted segment has a
// different IPv4 Identification value than the original segment.
func TestIPv4RetransmitIdentificationUniqueness(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload []byte
	}{
		{"SmallPayload", []byte("sample data")},
		// 512 bytes is chosen because sending more than this in a single segment
		// causes the retransmission to send less than the original amount.
		{"512BytePayload", testbench.GenerateRandomPayload(t, 512)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dut := testbench.NewDUT(t)
			listenFD, remotePort := dut.CreateListener(t, unix.SOCK_STREAM, unix.IPPROTO_TCP, 1)
			defer dut.Close(t, listenFD)

			conn := dut.Net.NewTCPIPv4(t, testbench.TCP{DstPort: &remotePort}, testbench.TCP{SrcPort: &remotePort})
			defer conn.Close(t)

			conn.Connect(t)
			remoteFD, _ := dut.Accept(t, listenFD)
			defer dut.Close(t, remoteFD)

			dut.SetSockOptInt(t, remoteFD, unix.IPPROTO_TCP, unix.TCP_NODELAY, 1)

			// TODO(b/129291778) The following socket option clears the DF bit on
			// IP packets sent over the socket, and is currently not supported by
			// gVisor. gVisor by default sends packets with DF=0 anyway, so the
			// socket option being not supported does not affect the operation of
			// this test. Once the socket option is supported, the following call
			// can be changed to simply assert success.
			ret, errno := dut.SetSockOptIntWithErrno(context.Background(), t, remoteFD, unix.IPPROTO_IP, linux.IP_MTU_DISCOVER, linux.IP_PMTUDISC_DONT)
			// Fuchsia will return ENOPROTOPT errno.
			if ret == -1 && errno != unix.ENOPROTOOPT {
				t.Fatalf("failed to set IP_MTU_DISCOVER socket option to IP_PMTUDISC_DONT: %s", errno)
			}

			samplePayload := &testbench.Payload{Bytes: tc.payload}

			dut.Send(t, remoteFD, tc.payload, 0)
			if _, err := conn.ExpectData(t, &testbench.TCP{}, samplePayload, time.Second); err != nil {
				t.Fatalf("failed to receive TCP segment sent for RTT calculation: %s", err)
			}
			// Let the DUT estimate RTO with RTT from the DATA-ACK.
			// TODO(gvisor.dev/issue/2685) Estimate RTO during handshake, after which
			// we can skip sending this ACK.
			conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)})

			dut.Send(t, remoteFD, tc.payload, 0)
			expectTCP := &testbench.TCP{SeqNum: testbench.Uint32(uint32(*conn.RemoteSeqNum(t)))}
			originalID, err := recvTCPSegment(t, &conn, expectTCP, samplePayload)
			if err != nil {
				t.Fatalf("failed to receive TCP segment: %s", err)
			}

			retransmitID, err := recvTCPSegment(t, &conn, expectTCP, samplePayload)
			if err != nil {
				t.Fatalf("failed to receive retransmitted TCP segment: %s", err)
			}
			if originalID == retransmitID {
				t.Fatalf("unexpectedly got retransmitted TCP segment with same IPv4 ID field=%d", originalID)
			}
		})
	}
}
