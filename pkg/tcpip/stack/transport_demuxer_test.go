// Copyright 2018 The gVisor Authors.
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

package stack_test

import (
	"io/ioutil"
	"math"
	"math/rand"
	"strconv"
	"testing"

	"gvisor.dev/gvisor/pkg/bufferv2"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/ports"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	testSrcAddrV6 = "\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
	testDstAddrV6 = tcpip.Address("\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02")

	testSrcAddrV4 = "\x0a\x00\x00\x01"
	testDstAddrV4 = "\x0a\x00\x00\x02"

	testDstPort = 1234
	testSrcPort = 4096
)

type testContext struct {
	linkEps map[tcpip.NICID]*channel.Endpoint
	s       *stack.Stack
	wq      waiter.Queue
}

// newDualTestContextMultiNIC creates the testing context and also linkEpIDs NICs.
func newDualTestContextMultiNIC(t *testing.T, mtu uint32, linkEpIDs []tcpip.NICID) *testContext {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
	})
	linkEps := make(map[tcpip.NICID]*channel.Endpoint)
	for _, linkEpID := range linkEpIDs {
		channelEp := channel.New(256, mtu, "")
		if err := s.CreateNIC(linkEpID, channelEp); err != nil {
			t.Fatalf("CreateNIC failed: %s", err)
		}
		linkEps[linkEpID] = channelEp

		protocolAddrV4 := tcpip.ProtocolAddress{
			Protocol:          ipv4.ProtocolNumber,
			AddressWithPrefix: tcpip.Address(testDstAddrV4).WithPrefix(),
		}
		if err := s.AddProtocolAddress(linkEpID, protocolAddrV4, stack.AddressProperties{}); err != nil {
			t.Fatalf("AddProtocolAddress(%d, %+v, {}): %s", linkEpID, protocolAddrV4, err)
		}

		protocolAddrV6 := tcpip.ProtocolAddress{
			Protocol:          ipv6.ProtocolNumber,
			AddressWithPrefix: testDstAddrV6.WithPrefix(),
		}
		if err := s.AddProtocolAddress(linkEpID, protocolAddrV6, stack.AddressProperties{}); err != nil {
			t.Fatalf("AddProtocolAddress(%d, %+v, {}): %s", linkEpID, protocolAddrV6, err)
		}
	}

	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: 1},
		{Destination: header.IPv6EmptySubnet, NIC: 1},
	})

	return &testContext{
		s:       s,
		linkEps: linkEps,
	}
}

type headers struct {
	srcPort uint16
	dstPort uint16
}

func newPayload() []byte {
	b := make([]byte, 30+rand.Intn(100))
	for i := range b {
		b[i] = byte(rand.Intn(256))
	}
	return b
}

func (c *testContext) sendV4Packet(payload []byte, h *headers, linkEpID tcpip.NICID) {
	buf := make([]byte, header.UDPMinimumSize+header.IPv4MinimumSize+len(payload))
	payloadStart := len(buf) - len(payload)
	copy(buf[payloadStart:], payload)

	// Initialize the IP header.
	ip := header.IPv4(buf)
	ip.Encode(&header.IPv4Fields{
		TOS:         0x80,
		TotalLength: uint16(len(buf)),
		TTL:         65,
		Protocol:    uint8(udp.ProtocolNumber),
		SrcAddr:     testSrcAddrV4,
		DstAddr:     testDstAddrV4,
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	// Initialize the UDP header.
	u := header.UDP(buf[header.IPv4MinimumSize:])
	u.Encode(&header.UDPFields{
		SrcPort: h.srcPort,
		DstPort: h.dstPort,
		Length:  uint16(header.UDPMinimumSize + len(payload)),
	})

	// Calculate the UDP pseudo-header checksum.
	xsum := header.PseudoHeaderChecksum(udp.ProtocolNumber, testSrcAddrV4, testDstAddrV4, uint16(len(u)))

	// Calculate the UDP checksum and set it.
	xsum = checksum.Checksum(payload, xsum)
	u.SetChecksum(^u.CalculateChecksum(xsum))

	// Inject packet.
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: bufferv2.MakeWithData(buf),
	})
	c.linkEps[linkEpID].InjectInbound(ipv4.ProtocolNumber, pkt)
}

func (c *testContext) sendV6Packet(payload []byte, h *headers, linkEpID tcpip.NICID) {
	// Allocate a buffer for data and headers.
	buf := make([]byte, header.UDPMinimumSize+header.IPv6MinimumSize+len(payload))
	copy(buf[len(buf)-len(payload):], payload)

	// Initialize the IP header.
	ip := header.IPv6(buf)
	ip.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(header.UDPMinimumSize + len(payload)),
		TransportProtocol: udp.ProtocolNumber,
		HopLimit:          65,
		SrcAddr:           testSrcAddrV6,
		DstAddr:           testDstAddrV6,
	})

	// Initialize the UDP header.
	u := header.UDP(buf[header.IPv6MinimumSize:])
	u.Encode(&header.UDPFields{
		SrcPort: h.srcPort,
		DstPort: h.dstPort,
		Length:  uint16(header.UDPMinimumSize + len(payload)),
	})

	// Calculate the UDP pseudo-header checksum.
	xsum := header.PseudoHeaderChecksum(udp.ProtocolNumber, testSrcAddrV6, testDstAddrV6, uint16(len(u)))

	// Calculate the UDP checksum and set it.
	xsum = checksum.Checksum(payload, xsum)
	u.SetChecksum(^u.CalculateChecksum(xsum))

	// Inject packet.
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: bufferv2.MakeWithData(buf),
	})
	c.linkEps[linkEpID].InjectInbound(ipv6.ProtocolNumber, pkt)
}

func TestTransportDemuxerRegister(t *testing.T) {
	for _, test := range []struct {
		name  string
		proto tcpip.NetworkProtocolNumber
		want  tcpip.Error
	}{
		{"failure", ipv6.ProtocolNumber, &tcpip.ErrUnknownProtocol{}},
		{"success", ipv4.ProtocolNumber, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := stack.New(stack.Options{
				NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
				TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
			})
			var wq waiter.Queue
			ep, err := s.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
			if err != nil {
				t.Fatal(err)
			}
			tEP, ok := ep.(stack.TransportEndpoint)
			if !ok {
				t.Fatalf("%T does not implement stack.TransportEndpoint", ep)
			}
			if got, want := s.RegisterTransportEndpoint([]tcpip.NetworkProtocolNumber{test.proto}, udp.ProtocolNumber, stack.TransportEndpointID{}, tEP, ports.Flags{}, 0), test.want; got != want {
				t.Fatalf("s.RegisterTransportEndpoint(...) = %s, want %s", got, want)
			}
		})
	}
}

func TestTransportDemuxerRegisterMultiple(t *testing.T) {
	type test struct {
		flags ports.Flags
		want  tcpip.Error
	}
	for _, subtest := range []struct {
		name  string
		tests []test
	}{
		{"zeroFlags", []test{
			{ports.Flags{}, nil},
			{ports.Flags{}, &tcpip.ErrPortInUse{}},
		}},
		{"multibindFlags", []test{
			// Allow multiple registrations same TransportEndpointID with multibind flags.
			{ports.Flags{LoadBalanced: true, MostRecent: true}, nil},
			{ports.Flags{LoadBalanced: true, MostRecent: true}, nil},
			// Disallow registration w/same ID for a non-multibindflag.
			{ports.Flags{TupleOnly: true}, &tcpip.ErrPortInUse{}},
		}},
	} {
		t.Run(subtest.name, func(t *testing.T) {
			s := stack.New(stack.Options{
				NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
				TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
			})
			var eps []tcpip.Endpoint
			for idx, test := range subtest.tests {
				var wq waiter.Queue
				ep, err := s.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
				if err != nil {
					t.Fatal(err)
				}
				eps = append(eps, ep)
				tEP, ok := ep.(stack.TransportEndpoint)
				if !ok {
					t.Fatalf("%T does not implement stack.TransportEndpoint", ep)
				}
				id := stack.TransportEndpointID{LocalPort: 1}
				if got, want := s.RegisterTransportEndpoint([]tcpip.NetworkProtocolNumber{ipv4.ProtocolNumber}, udp.ProtocolNumber, id, tEP, test.flags, 0), test.want; got != want {
					t.Fatalf("test index: %d, s.RegisterTransportEndpoint(ipv4.ProtocolNumber, udp.ProtocolNumber, _, _, %+v, 0) = %s, want %s", idx, test.flags, got, want)
				}
			}
			for _, ep := range eps {
				ep.Close()
			}
		})
	}
}

// TestBindToDeviceDistribution injects varied packets on input devices and checks that
// the distribution of packets received matches expectations.
func TestBindToDeviceDistribution(t *testing.T) {
	type endpointSockopts struct {
		reuse        bool
		bindToDevice tcpip.NICID
	}
	tcs := []struct {
		name string
		// endpoints will received the inject packets.
		endpoints []endpointSockopts
		// wantDistributions is the want ratio of packets received on each
		// endpoint for each NIC on which packets are injected.
		wantDistributions map[tcpip.NICID][]float64
	}{
		{
			name: "BindPortReuse",
			// 5 endpoints that all have reuse set.
			endpoints: []endpointSockopts{
				{reuse: true, bindToDevice: 0},
				{reuse: true, bindToDevice: 0},
				{reuse: true, bindToDevice: 0},
				{reuse: true, bindToDevice: 0},
				{reuse: true, bindToDevice: 0},
			},
			wantDistributions: map[tcpip.NICID][]float64{
				// Injected packets on dev0 get distributed evenly.
				1: {0.2, 0.2, 0.2, 0.2, 0.2},
			},
		},
		{
			name: "BindToDevice",
			// 3 endpoints with various bindings.
			endpoints: []endpointSockopts{
				{reuse: false, bindToDevice: 1},
				{reuse: false, bindToDevice: 2},
				{reuse: false, bindToDevice: 3},
			},
			wantDistributions: map[tcpip.NICID][]float64{
				// Injected packets on dev0 go only to the endpoint bound to dev0.
				1: {1, 0, 0},
				// Injected packets on dev1 go only to the endpoint bound to dev1.
				2: {0, 1, 0},
				// Injected packets on dev2 go only to the endpoint bound to dev2.
				3: {0, 0, 1},
			},
		},
		{
			name: "ReuseAndBindToDevice",
			// 6 endpoints with various bindings.
			endpoints: []endpointSockopts{
				{reuse: true, bindToDevice: 1},
				{reuse: true, bindToDevice: 1},
				{reuse: true, bindToDevice: 2},
				{reuse: true, bindToDevice: 2},
				{reuse: true, bindToDevice: 2},
				{reuse: true, bindToDevice: 0},
			},
			wantDistributions: map[tcpip.NICID][]float64{
				// Injected packets on dev0 get distributed among endpoints bound to
				// dev0.
				1: {0.5, 0.5, 0, 0, 0, 0},
				// Injected packets on dev1 get distributed among endpoints bound to
				// dev1 or unbound.
				2: {0, 0, 1. / 3, 1. / 3, 1. / 3, 0},
				// Injected packets on dev999 go only to the unbound.
				1000: {0, 0, 0, 0, 0, 1},
			},
		},
	}
	protos := map[string]tcpip.NetworkProtocolNumber{
		"IPv4": ipv4.ProtocolNumber,
		"IPv6": ipv6.ProtocolNumber,
	}

	for _, test := range tcs {
		for protoName, protoNum := range protos {
			for device, wantDistribution := range test.wantDistributions {
				t.Run(test.name+protoName+"-"+strconv.Itoa(int(device)), func(t *testing.T) {
					// Create the NICs.
					var devices []tcpip.NICID
					for d := range test.wantDistributions {
						devices = append(devices, d)
					}
					c := newDualTestContextMultiNIC(t, defaultMTU, devices)

					// Create endpoints and bind each to a NIC, sometimes reusing ports.
					eps := make(map[tcpip.Endpoint]int)
					pollChannel := make(chan tcpip.Endpoint)
					for i, endpoint := range test.endpoints {
						// Try to receive the data.
						wq := waiter.Queue{}
						we, ch := waiter.NewChannelEntry(waiter.ReadableEvents)
						wq.EventRegister(&we)
						t.Cleanup(func() {
							wq.EventUnregister(&we)
							close(ch)
						})

						var err tcpip.Error
						ep, err := c.s.NewEndpoint(udp.ProtocolNumber, protoNum, &wq)
						if err != nil {
							t.Fatalf("NewEndpoint failed: %s", err)
						}
						t.Cleanup(ep.Close)
						eps[ep] = i

						go func(ep tcpip.Endpoint) {
							for range ch {
								pollChannel <- ep
							}
						}(ep)

						ep.SocketOptions().SetReusePort(endpoint.reuse)
						if err := ep.SocketOptions().SetBindToDevice(int32(endpoint.bindToDevice)); err != nil {
							t.Fatalf("SetSockOpt(&%T(%d)) on endpoint %d failed: %s", endpoint.bindToDevice, endpoint.bindToDevice, i, err)
						}

						var dstAddr tcpip.Address
						switch protoNum {
						case ipv4.ProtocolNumber:
							dstAddr = testDstAddrV4
						case ipv6.ProtocolNumber:
							dstAddr = testDstAddrV6
						default:
							t.Fatalf("unexpected protocol number: %d", protoNum)
						}
						if err := ep.Bind(tcpip.FullAddress{Addr: dstAddr, Port: testDstPort}); err != nil {
							t.Fatalf("ep.Bind(...) on endpoint %d failed: %s", i, err)
						}
					}

					// Send packets across a range of ports, checking that packets from
					// the same source port are always demultiplexed to the same
					// destination endpoint.
					npackets := 10_000
					nports := 1_000
					if got, want := len(test.endpoints), len(wantDistribution); got != want {
						t.Fatalf("got len(test.endpoints) = %d, want %d", got, want)
					}
					endpoints := make(map[uint16]tcpip.Endpoint)
					stats := make(map[tcpip.Endpoint]int)
					for i := 0; i < npackets; i++ {
						// Send a packet.
						port := uint16(i % nports)
						payload := newPayload()
						hdrs := &headers{
							srcPort: testSrcPort + port,
							dstPort: testDstPort,
						}
						switch protoNum {
						case ipv4.ProtocolNumber:
							c.sendV4Packet(payload, hdrs, device)
						case ipv6.ProtocolNumber:
							c.sendV6Packet(payload, hdrs, device)
						default:
							t.Fatalf("unexpected protocol number: %d", protoNum)
						}

						ep := <-pollChannel
						if _, err := ep.Read(ioutil.Discard, tcpip.ReadOptions{}); err != nil {
							t.Fatalf("Read on endpoint %d failed: %s", eps[ep], err)
						}
						stats[ep]++
						if i < nports {
							endpoints[uint16(i)] = ep
						} else {
							// Check that all packets from one client are handled by the same
							// socket.
							if want, got := endpoints[port], ep; want != got {
								t.Fatalf("Packet sent on port %d expected on endpoint %d but received on endpoint %d", port, eps[want], eps[got])
							}
						}
					}

					// Check that a packet distribution is as expected.
					for ep, i := range eps {
						wantRatio := wantDistribution[i]
						wantRecv := wantRatio * float64(npackets)
						actualRecv := stats[ep]
						actualRatio := float64(stats[ep]) / float64(npackets)
						// The deviation is less than 10%.
						if math.Abs(actualRatio-wantRatio) > 0.05 {
							t.Errorf("want about %.0f%% (%.0f of %d) packets to arrive on endpoint %d, got %.0f%% (%d of %d)", wantRatio*100, wantRecv, npackets, i, actualRatio*100, actualRecv, npackets)
						}
					}
				})
			}
		}
	}
}
