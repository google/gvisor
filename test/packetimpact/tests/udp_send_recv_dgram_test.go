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

package udp_send_recv_dgram_test

import (
	"context"
	"flag"
	"fmt"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

func init() {
	testbench.Initialize(flag.CommandLine)
	testbench.RPCTimeout = 500 * time.Millisecond
}

type udpConn interface {
	SrcPort(*testing.T) uint16
	SendFrame(*testing.T, testbench.Layers, ...testbench.Layer)
	ExpectFrame(*testing.T, testbench.Layers, time.Duration) (testbench.Layers, error)
	Close(*testing.T)
}

type testCase struct {
	bindTo, sendTo                            net.IP
	sendToBroadcast, bindToDevice, expectData bool
}

func TestUDP(t *testing.T) {
	dut := testbench.NewDUT(t)
	subnetBcast := func() net.IP {
		subnet := (&tcpip.AddressWithPrefix{
			Address:   tcpip.Address(dut.Net.RemoteIPv4.To4()),
			PrefixLen: dut.Net.IPv4PrefixLength,
		}).Subnet()
		return net.IP(subnet.Broadcast())
	}()

	t.Run("Send", func(t *testing.T) {
		var testCases []testCase
		// Test every valid combination of bound/unbound, broadcast/multicast/unicast
		// bound/destination address, and bound/not-bound to device.
		for _, bindTo := range []net.IP{
			nil, // Do not bind.
			net.IPv4zero,
			net.IPv4bcast,
			net.IPv4allsys,
			subnetBcast,
			dut.Net.RemoteIPv4,
			dut.Net.RemoteIPv6,
		} {
			for _, sendTo := range []net.IP{
				net.IPv4bcast,
				net.IPv4allsys,
				subnetBcast,
				dut.Net.LocalIPv4,
				dut.Net.LocalIPv6,
			} {
				// Cannot send to an IPv4 address from a socket bound to IPv6 (except for IPv4-mapped IPv6),
				// and viceversa.
				if bindTo != nil && ((bindTo.To4() == nil) != (sendTo.To4() == nil)) {
					continue
				}
				for _, bindToDevice := range []bool{true, false} {
					expectData := true
					switch {
					case bindTo.Equal(dut.Net.RemoteIPv4):
						// If we're explicitly bound to an interface's unicast address,
						// packets are always sent on that interface.
					case bindToDevice:
						// If we're explicitly bound to an interface, packets are always
						// sent on that interface.
					case !sendTo.Equal(net.IPv4bcast) && !sendTo.IsMulticast():
						// If we're not sending to limited broadcast or multicast, the route table
						// will be consulted and packets will be sent on the correct interface.
					default:
						expectData = false
					}
					testCases = append(
						testCases,
						testCase{
							bindTo:          bindTo,
							sendTo:          sendTo,
							sendToBroadcast: sendTo.Equal(subnetBcast) || sendTo.Equal(net.IPv4bcast),
							bindToDevice:    bindToDevice,
							expectData:      expectData,
						},
					)
				}
			}
		}
		for _, tc := range testCases {
			boundTestCaseName := "unbound"
			if tc.bindTo != nil {
				boundTestCaseName = fmt.Sprintf("bindTo=%s", tc.bindTo)
			}
			t.Run(fmt.Sprintf("%s/sendTo=%s/bindToDevice=%t/expectData=%t", boundTestCaseName, tc.sendTo, tc.bindToDevice, tc.expectData), func(t *testing.T) {
				runTestCase(
					t,
					dut,
					tc,
					func(t *testing.T, dut testbench.DUT, conn udpConn, socketFD int32, tc testCase, payload []byte, layers testbench.Layers) {
						var destSockaddr unix.Sockaddr
						if sendTo4 := tc.sendTo.To4(); sendTo4 != nil {
							addr := unix.SockaddrInet4{
								Port: int(conn.SrcPort(t)),
							}
							copy(addr.Addr[:], sendTo4)
							destSockaddr = &addr
						} else {
							addr := unix.SockaddrInet6{
								Port:   int(conn.SrcPort(t)),
								ZoneId: dut.Net.RemoteDevID,
							}
							copy(addr.Addr[:], tc.sendTo.To16())
							destSockaddr = &addr
						}
						if got, want := dut.SendTo(t, socketFD, payload, 0, destSockaddr), len(payload); int(got) != want {
							t.Fatalf("got dut.SendTo = %d, want %d", got, want)
						}
						layers = append(layers, &testbench.Payload{
							Bytes: payload,
						})
						_, err := conn.ExpectFrame(t, layers, time.Second)

						if !tc.expectData && err == nil {
							t.Fatal("received unexpected packet, socket is not bound to device")
						}
						if err != nil && tc.expectData {
							t.Fatal(err)
						}
					},
				)
			})
		}
	})
	t.Run("Recv", func(t *testing.T) {
		// Test every valid combination of broadcast/multicast/unicast
		// bound/destination address, and bound/not-bound to device.
		var testCases []testCase
		for _, addr := range []net.IP{
			net.IPv4bcast,
			net.IPv4allsys,
			dut.Net.RemoteIPv4,
			dut.Net.RemoteIPv6,
		} {
			for _, bindToDevice := range []bool{true, false} {
				testCases = append(
					testCases,
					testCase{
						bindTo:          addr,
						sendTo:          addr,
						sendToBroadcast: addr.Equal(subnetBcast) || addr.Equal(net.IPv4bcast),
						bindToDevice:    bindToDevice,
						expectData:      true,
					},
				)
			}
		}
		for _, bindTo := range []net.IP{
			net.IPv4zero,
			subnetBcast,
			dut.Net.RemoteIPv4,
		} {
			for _, sendTo := range []net.IP{
				subnetBcast,
				net.IPv4bcast,
				net.IPv4allsys,
			} {
				// TODO(gvisor.dev/issue/4896): Add bindTo=subnetBcast/sendTo=IPv4bcast
				// and bindTo=subnetBcast/sendTo=IPv4allsys test cases.
				if bindTo.Equal(subnetBcast) && (sendTo.Equal(net.IPv4bcast) || sendTo.IsMulticast()) {
					continue
				}
				// Expect that a socket bound to a unicast address does not receive
				// packets sent to an address other than the bound unicast address.
				//
				// Note: we cannot use net.IP.IsGlobalUnicast to test this condition
				// because IsGlobalUnicast does not check whether the address is the
				// subnet broadcast, and returns true in that case.
				expectData := !bindTo.Equal(dut.Net.RemoteIPv4) || sendTo.Equal(dut.Net.RemoteIPv4)
				for _, bindToDevice := range []bool{true, false} {
					testCases = append(
						testCases,
						testCase{
							bindTo:          bindTo,
							sendTo:          sendTo,
							sendToBroadcast: sendTo.Equal(subnetBcast) || sendTo.Equal(net.IPv4bcast),
							bindToDevice:    bindToDevice,
							expectData:      expectData,
						},
					)
				}
			}
		}
		for _, tc := range testCases {
			t.Run(fmt.Sprintf("bindTo=%s/sendTo=%s/bindToDevice=%t/expectData=%t", tc.bindTo, tc.sendTo, tc.bindToDevice, tc.expectData), func(t *testing.T) {
				runTestCase(
					t,
					dut,
					tc,
					func(t *testing.T, dut testbench.DUT, conn udpConn, socketFD int32, tc testCase, payload []byte, layers testbench.Layers) {
						conn.SendFrame(t, layers, &testbench.Payload{Bytes: payload})

						if tc.expectData {
							got, want := dut.Recv(t, socketFD, int32(len(payload)+1), 0), payload
							if diff := cmp.Diff(want, got); diff != "" {
								t.Errorf("received payload does not match sent payload, diff (-want, +got):\n%s", diff)
							}
						} else {
							// Expected receive error, set a short receive timeout.
							dut.SetSockOptTimeval(
								t,
								socketFD,
								unix.SOL_SOCKET,
								unix.SO_RCVTIMEO,
								&unix.Timeval{
									Sec:  1,
									Usec: 0,
								},
							)
							ret, recvPayload, errno := dut.RecvWithErrno(context.Background(), t, socketFD, 100, 0)
							if errno != syscall.EAGAIN || errno != syscall.EWOULDBLOCK {
								t.Errorf("Recv got unexpected result, ret=%d, payload=%q, errno=%s", ret, recvPayload, errno)
							}
						}
					},
				)
			})
		}
	})
}

func runTestCase(
	t *testing.T,
	dut testbench.DUT,
	tc testCase,
	runTc func(t *testing.T, dut testbench.DUT, conn udpConn, socketFD int32, tc testCase, payload []byte, layers testbench.Layers),
) {
	var (
		socketFD                 int32
		outgoingUDP, incomingUDP testbench.UDP
	)
	if tc.bindTo != nil {
		var remotePort uint16
		socketFD, remotePort = dut.CreateBoundSocket(t, unix.SOCK_DGRAM, unix.IPPROTO_UDP, tc.bindTo)
		outgoingUDP.DstPort = &remotePort
		incomingUDP.SrcPort = &remotePort
	} else {
		// An unbound socket will auto-bind to INNADDR_ANY and a random
		// port on sendto.
		socketFD = dut.Socket(t, unix.AF_INET6, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
	}
	defer dut.Close(t, socketFD)
	if tc.bindToDevice {
		dut.SetSockOpt(t, socketFD, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, []byte(dut.Net.RemoteDevName))
	}

	var ethernetLayer testbench.Ether
	if tc.sendToBroadcast {
		dut.SetSockOptInt(t, socketFD, unix.SOL_SOCKET, unix.SO_BROADCAST, 1)

		// When sending to broadcast (subnet or limited), the expected ethernet
		// address is also broadcast.
		ethernetBroadcastAddress := header.EthernetBroadcastAddress
		ethernetLayer.DstAddr = &ethernetBroadcastAddress
	} else if tc.sendTo.IsMulticast() {
		ethernetMulticastAddress := header.EthernetAddressFromMulticastIPv4Address(tcpip.Address(tc.sendTo.To4()))
		ethernetLayer.DstAddr = &ethernetMulticastAddress
	}
	expectedLayers := testbench.Layers{&ethernetLayer}

	var conn udpConn
	if sendTo4 := tc.sendTo.To4(); sendTo4 != nil {
		v4Conn := dut.Net.NewUDPIPv4(t, outgoingUDP, incomingUDP)
		conn = &v4Conn
		expectedLayers = append(
			expectedLayers,
			&testbench.IPv4{
				DstAddr: testbench.Address(tcpip.Address(sendTo4)),
			},
		)
	} else {
		v6Conn := dut.Net.NewUDPIPv6(t, outgoingUDP, incomingUDP)
		conn = &v6Conn
		expectedLayers = append(
			expectedLayers,
			&testbench.IPv6{
				DstAddr: testbench.Address(tcpip.Address(tc.sendTo)),
			},
		)
	}
	defer conn.Close(t)

	expectedLayers = append(expectedLayers, &incomingUDP)
	for _, v := range []struct {
		name    string
		payload []byte
	}{
		{"emptypayload", nil},
		{"small payload", []byte("hello world")},
		{"1kPayload", testbench.GenerateRandomPayload(t, 1<<10)},
		// Even though UDP allows larger dgrams we don't test it here as
		// they need to be fragmented and written out as individual
		// frames.
	} {
		runTc(t, dut, conn, socketFD, tc, v.payload, expectedLayers)
	}
}
