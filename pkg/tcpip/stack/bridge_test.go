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

package bridge_test

import (
	"os"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/ethernet"
	"gvisor.dev/gvisor/pkg/tcpip/link/veth"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func TestWritePacketFromBridge(t *testing.T) {
	const (
		channelLinkAddr1 = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x05")
		channelLinkAddr2 = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x06")
		remoteLinkAddr   = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x07")
		bridgeLinkAddr   = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x08")

		netProto = 55
		nicID1   = 5
		nicID2   = 6
		bridgeID = 7
	)

	// Create two channel-based endpoints as receivers, they are both
	// bound to the same bridge device and are both expected to receive the
	// packets that are written by the bridge.
	ch1 := channel.New(1, header.EthernetMinimumSize, channelLinkAddr1)
	ch2 := channel.New(1, header.EthernetMinimumSize, channelLinkAddr2)
	bridgeEndpoint := stack.NewBridgeEndpoint(1500)
	bridgeEndpoint.SetLinkAddress(bridgeLinkAddr)
	s := stack.New(stack.Options{})

	if err := s.CreateNIC(nicID1, ethernet.New(ch1)); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", nicID1, err)
	}
	if err := s.CreateNIC(nicID2, ethernet.New(ch2)); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", nicID2, err)
	}
	if err := s.CreateNIC(bridgeID, bridgeEndpoint); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", bridgeID, err)
	}
	if err := s.SetNICCoordinator(nicID1, bridgeID); err != nil {
		t.Fatalf("s.SetNICCoordinator(%d, %d)", nicID1, bridgeID)
	}
	if err := s.SetNICCoordinator(nicID2, bridgeID); err != nil {
		t.Fatalf("s.SetNICCoordinator(%d, %d)", nicID2, bridgeID)
	}
	// When writing packets, the bridge will try all available bridge ports.
	if err := s.WritePacketToRemote(bridgeID, remoteLinkAddr, netProto, buffer.Buffer{}); err != nil {
		t.Fatalf("s.WritePacketToRemote(%d, %s, _): %s", bridgeID, remoteLinkAddr, err)
	}
	for _, c := range []*channel.Endpoint{ch1, ch2} {
		pkt := c.Read()
		if pkt == nil {
			t.Fatal("expected to read a packet")
		}

		eth := header.Ethernet(pkt.LinkHeader().Slice())
		pkt.DecRef()
		if got := eth.SourceAddress(); got != bridgeLinkAddr {
			t.Errorf("got eth.SourceAddress() = %s, want = %s", got, bridgeLinkAddr)
		}
		if got := eth.DestinationAddress(); got != remoteLinkAddr {
			t.Errorf("got eth.DestinationAddress() = %s, want = %s", got, remoteLinkAddr)
		}
		if got := eth.Type(); got != netProto {
			t.Errorf("got eth.Type() = %d, want = %d", got, netProto)
		}
	}
}

type testNotification struct {
	ch chan bool
}

func (n *testNotification) WriteNotify() {
	n.ch <- true
}

// The test verifies that packates that are forwarded by
// a bridge will flooded to all bridge ports.
func TestWritePacketBetweenDevices(t *testing.T) {
	const (
		channelLinkAddr1 = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x04")
		channelLinkAddr2 = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x05")
		vethLinkAddr1    = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x06")
		vethLinkAddr2    = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x07")
		remoteLinkAddr   = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x08")
		bridgeLinkAddr   = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x09")

		netProto = 55
		nicID1   = 4
		nicID2   = 5
		vethID   = 6
		bridgeID = 9
	)
	// Creates a pair of veth devices which will be attached to different
	// network stacks.
	veth1, veth2 := veth.NewPair(1500, veth.DefaultBacklogSize)
	veth1.SetLinkAddress(vethLinkAddr1)
	veth2.SetLinkAddress(vethLinkAddr2)
	ch1 := channel.New(1, header.EthernetMinimumSize, channelLinkAddr1)
	ch2 := channel.New(1, header.EthernetMinimumSize, channelLinkAddr2)

	bridgeEndpoint := stack.NewBridgeEndpoint(1500)
	bridgeEndpoint.SetLinkAddress(bridgeLinkAddr)
	s := stack.New(stack.Options{})
	secondStack := stack.New(stack.Options{})
	if err := s.CreateNIC(bridgeID, bridgeEndpoint); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", bridgeID, err)
	}
	if err := s.CreateNIC(nicID1, ethernet.New(ch1)); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", nicID1, err)
	}
	if err := s.SetNICCoordinator(nicID1, bridgeID); err != nil {
		t.Fatalf("s.SetNICCoordinator(%d, %d)", nicID1, bridgeID)
	}
	if err := s.CreateNIC(nicID2, ethernet.New(ch2)); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", nicID2, err)
	}
	if err := s.SetNICCoordinator(nicID2, bridgeID); err != nil {
		t.Fatalf("s.SetNICCoordinator(%d, %d)", nicID2, bridgeID)
	}
	if err := s.CreateNIC(vethID, ethernet.New(veth1)); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", vethID, err)
	}
	// Attach one veth device to stack s, and attach the other
	// veth to stack secondStack.
	if err := s.SetNICCoordinator(vethID, bridgeID); err != nil {
		t.Fatalf("s.SetNICCoordinator")
	}
	if err := secondStack.CreateNIC(vethID, ethernet.New(veth2)); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", vethID, err)
	}

	n1 := &testNotification{ch: make(chan bool, 1)}
	n2 := &testNotification{ch: make(chan bool, 1)}
	ch1.AddNotify(n1)
	ch2.AddNotify(n2)
	// Write a packet to the veth device at the stack secondStack, the packet
	// will be available at the veth device at the stack s.
	if err := secondStack.WritePacketToRemote(vethID, remoteLinkAddr, netProto, buffer.Buffer{}); err != nil {
		t.Fatalf("s.WritePacketToRemote(%d, %s, _): %s", bridgeID, remoteLinkAddr, err)
	}
	<-n1.ch
	<-n2.ch
	// No FDB entry, a package floods all bridge ports except the port that
	// is attached to the veth device.
	for _, c := range []*channel.Endpoint{ch1, ch2} {
		pkt := c.Read()
		if pkt == nil {
			t.Fatal("expected to read a packet")
		}

		pkt.LinkHeader().Consume(header.EthernetMinimumSize)
		eth := header.Ethernet(pkt.LinkHeader().Slice())
		pkt.DecRef()
		if got := eth.SourceAddress(); got != vethLinkAddr2 {
			t.Errorf("got eth.SourceAddress() = %s, want = %s", got, vethLinkAddr2)
		}
		if got := eth.DestinationAddress(); got != remoteLinkAddr {
			t.Errorf("got eth.DestinationAddress() = %s, want = %s", got, remoteLinkAddr)
		}
		if got := eth.Type(); got != netProto {
			t.Errorf("got eth.Type() = %d, want = %d", got, netProto)
		}
	}
}

func TestBridgeFDB(t *testing.T) {
	const (
		channelLinkAddr = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x03")
		remoteLinkAddr  = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x08")
		bridgeLinkAddr  = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x09")

		netProto = 55
		nicID    = 4
		vethID1  = 7
		vethID2  = 8
		bridgeID = 9
	)
	veth1, veth2 := veth.NewPair(1500, veth.DefaultBacklogSize)
	ch := channel.New(1, header.EthernetMinimumSize, channelLinkAddr)
	bridgeEndpoint := stack.NewBridgeEndpoint(1500)
	bridgeEndpoint.SetLinkAddress(bridgeLinkAddr)
	s := stack.New(stack.Options{})
	secondStack := stack.New(stack.Options{})

	if err := s.CreateNIC(bridgeID, bridgeEndpoint); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", bridgeID, err)
	}
	if err := s.CreateNIC(nicID, ethernet.New(ch)); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", nicID, err)
	}
	if err := s.SetNICCoordinator(nicID, bridgeID); err != nil {
		t.Fatalf("s.SetNICCoordinator(%d, %d)", nicID, bridgeID)
	}
	if err := s.CreateNIC(vethID1, ethernet.New(veth1)); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", vethID1, err)
	}
	if err := s.SetNICCoordinator(vethID1, bridgeID); err != nil {
		t.Fatalf("s.SetNICCoordinator(%d, %d)", vethID1, bridgeID)
	}
	if err := secondStack.CreateNIC(vethID2, ethernet.New(veth2)); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", vethID2, err)
	}
	n := &testNotification{ch: make(chan bool, 1)}
	ch.AddNotify(n)
	// Write a packet to the veth device at secondStack, the
	// packet will be available at stack s via veth.
	if err := secondStack.WritePacketToRemote(vethID2, remoteLinkAddr, netProto, buffer.Buffer{}); err != nil {
		t.Fatalf("s.WritePacketToRemote(%d, %s, _): %s", bridgeID, remoteLinkAddr, err)
	}
	<-n.ch
	pkt := ch.Read()
	defer pkt.DecRef()
	if pkt == nil {
		t.Fatal("expected to read a packet")
	}
	// When forwarding the packet via the bridge device, the packet's
	// source MAC address will be used as lookup key to the bridge
	// FDB.
	var e stack.BridgeFDBEntry
	start := time.Now()
	for {
		e = bridgeEndpoint.FindFDBEntry(veth2.LinkAddress())
		if len(e.PortLinkAddress()) != 0 {
			break
		}
		if time.Since(start) > 30*time.Second {
			t.Fatalf("failed to find FDB entry for %s after 30 seconds", veth2.LinkAddress())
		}
		time.Sleep(time.Second)
	}
	if e.PortLinkAddress() != veth1.LinkAddress() {
		t.Fatalf("bridgeEndpoint.FindFDBEntry(%s) = %s, want = %s", veth2.LinkAddress(), e.PortLinkAddress(), veth1.LinkAddress())
	}
	// No FDB entry is expected for devices other than veth1.
	if e := bridgeEndpoint.FindFDBEntry(channelLinkAddr); len(e.PortLinkAddress()) != 0 {
		t.Fatalf("bridgeEndpoint.FindFDBEntry(%s) = %s, want = \"\"", channelLinkAddr, e.PortLinkAddress())
	}
}

func TestSetCoordinator(t *testing.T) {
	const (
		bridgeLinkAddr = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x08")
		bridgeID       = 6
	)

	s := stack.New(stack.Options{})
	bridgeEndpoint := stack.NewBridgeEndpoint(1500)
	bridgeEndpoint.SetLinkAddress(bridgeLinkAddr)
	if err := s.CreateNIC(bridgeID, bridgeEndpoint); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", bridgeID, err)
	}
	if err := s.SetNICCoordinator(bridgeID, bridgeID); err == nil {
		t.Fatalf("s.SetNICCoordinator(%d, %d) = %s, want = %s", bridgeID, bridgeID, err, tcpip.ErrNoSuchFile{})
	}
}

func TestMTU(t *testing.T) {
	e := stack.NewBridgeEndpoint(1500)
	mtus := []uint32{1000, 2000}
	for _, mtu := range mtus {
		e.SetMTU(mtu)

		if want, v := mtu-header.EthernetMinimumSize, e.MTU(); want != v {
			t.Errorf("MTU() = %v, want %v", v, want)
		}
	}
}

func TestNicExitingStackExitsBridgeToo(t *testing.T) {
	const (
		netProto        = 55
		nicID           = 5
		bridgeID        = 7
		bridgeLinkAddr  = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x09")
		channelLinkAddr = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x04")
		remoteLinkAddr  = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x07")
	)

	src := stack.New(stack.Options{})

	// Create a bridge in src.
	bridgeEndpoint := stack.NewBridgeEndpoint(1500)
	bridgeEndpoint.SetLinkAddress(bridgeLinkAddr)
	if err := src.CreateNIC(bridgeID, bridgeEndpoint); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", bridgeID, err)
	}

	// Create a channel-endpoint-based nic in src.
	ch := channel.New(1, header.EthernetMinimumSize, channelLinkAddr)
	if err := src.CreateNIC(nicID, ethernet.New(ch)); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", nicID, err)
	}
	// And add it to the bridge.
	if err := src.SetNICCoordinator(nicID, bridgeID); err != nil {
		t.Fatalf("s.SetNICCoordinator(%d, %d)", nicID, bridgeID)
	}

	// The bridge should forward pkts to the nic.
	if err := src.WritePacketToRemote(bridgeID, remoteLinkAddr, netProto, buffer.Buffer{}); err != nil {
		t.Fatalf("s.WritePacketToRemote(%d, %s, _): %s", bridgeID, remoteLinkAddr, err)
	}
	pkt := ch.Read()
	if pkt == nil {
		t.Fatal("expected to read a packet")
	}
	pkt.DecRef()

	// Now move the nic into dst.
	dst := stack.New(stack.Options{})
	if _, err := src.SetNICStack(nicID, dst); err != nil {
		t.Fatalf("s.SetNICStack(%d, %p) = %s, want nil", nicID, dst, err)
	}

	// The bridge should no longer forward pkts to the nic, lest it defeat the purpose of network
	// namespaces.
	if err := src.WritePacketToRemote(bridgeID, remoteLinkAddr, netProto, buffer.Buffer{}); err != nil {
		t.Fatalf("s.WritePacketToRemote(%d, %s, _): %s", bridgeID, remoteLinkAddr, err)
	}
	pkt = ch.Read()
	if pkt != nil {
		pkt.DecRef()
		t.Fatal("did not expect to read a packet")
	}
}

// makeEthernetFrame builds an inbound frame whose ethernet header is still in
// the payload, for injection into a channel endpoint wrapped by ethernet.New.
func makeEthernetFrame(src, dst tcpip.LinkAddress) *stack.PacketBuffer {
	hdr := make([]byte, header.EthernetMinimumSize)
	header.Ethernet(hdr).Encode(&header.EthernetFields{
		SrcAddr: src,
		DstAddr: dst,
		Type:    header.IPv4ProtocolNumber,
	})
	return stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(hdr),
	})
}

// drainChannels releases every packet queued on the given endpoints.
func drainChannels(eps ...*channel.Endpoint) {
	for _, ep := range eps {
		for pkt := ep.Read(); pkt != nil; pkt = ep.Read() {
			pkt.DecRef()
		}
	}
}

// TestBridgeDispatchOnlyForLocalOrMulticast checks that only group frames and
// frames addressed to the bridge or to the receiving port are passed up; other
// frames are only forwarded.
func TestBridgeDispatchOnlyForLocalOrMulticast(t *testing.T) {
	const (
		channelLinkAddr1 = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x10")
		channelLinkAddr2 = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x11")
		bridgeLinkAddr   = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x12")
		unknownLinkAddr  = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x13")

		nicID1   = 11
		nicID2   = 12
		bridgeID = 13
	)

	tests := []struct {
		name       string
		dst        tcpip.LinkAddress
		wantUpcall bool
		// checkFwd checks that port 2 receives the frame. Frames for the bridge
		// or the receiving port are not checked because they are still flooded.
		checkFwd bool
	}{
		{name: "unicast to other port", dst: channelLinkAddr2, checkFwd: true},
		{name: "unknown unicast", dst: unknownLinkAddr, checkFwd: true},
		{name: "unicast to bridge", dst: bridgeLinkAddr, wantUpcall: true},
		{name: "unicast to receiving port", dst: channelLinkAddr1, wantUpcall: true},
		{name: "broadcast", dst: header.EthernetBroadcastAddress, wantUpcall: true, checkFwd: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ch1 := channel.New(1, header.EthernetMinimumSize, channelLinkAddr1)
			ch2 := channel.New(1, header.EthernetMinimumSize, channelLinkAddr2)
			bridgeEndpoint := stack.NewBridgeEndpoint(1500)
			bridgeEndpoint.SetLinkAddress(bridgeLinkAddr)

			s := stack.New(stack.Options{})
			defer s.Destroy()
			if err := s.CreateNIC(bridgeID, bridgeEndpoint); err != nil {
				t.Fatalf("s.CreateNIC(%d, _): %s", bridgeID, err)
			}
			if err := s.CreateNIC(nicID1, ethernet.New(ch1)); err != nil {
				t.Fatalf("s.CreateNIC(%d, _): %s", nicID1, err)
			}
			if err := s.CreateNIC(nicID2, ethernet.New(ch2)); err != nil {
				t.Fatalf("s.CreateNIC(%d, _): %s", nicID2, err)
			}
			if err := s.SetNICCoordinator(nicID1, bridgeID); err != nil {
				t.Fatalf("s.SetNICCoordinator(%d, %d): %s", nicID1, bridgeID, err)
			}
			if err := s.SetNICCoordinator(nicID2, bridgeID); err != nil {
				t.Fatalf("s.SetNICCoordinator(%d, %d): %s", nicID2, bridgeID, err)
			}

			// Learn port 2 so that frames to it are forwarded, not flooded.
			learn := makeEthernetFrame(channelLinkAddr2, channelLinkAddr1)
			ch2.InjectInbound(header.IPv4ProtocolNumber, learn)
			learn.DecRef()
			drainChannels(ch1, ch2)

			rx := s.NICInfo()[bridgeID].Stats.Rx.Packets
			before := rx.Value()
			pkt := makeEthernetFrame(channelLinkAddr1, test.dst)
			ch1.InjectInbound(header.IPv4ProtocolNumber, pkt)
			pkt.DecRef()

			var wantUpcalls uint64
			if test.wantUpcall {
				wantUpcalls = 1
			}
			if got := rx.Value() - before; got != wantUpcalls {
				t.Errorf("got %d frames passed up to the bridge, want %d", got, wantUpcalls)
			}
			if test.checkFwd {
				if fwd := ch2.Read(); fwd == nil {
					t.Error("frame was not forwarded to port 2")
				} else {
					fwd.LinkHeader().Consume(header.EthernetMinimumSize)
					if got := header.Ethernet(fwd.LinkHeader().Slice()).DestinationAddress(); got != test.dst {
						t.Errorf("got forwarded destination = %s, want = %s", got, test.dst)
					}
					fwd.DecRef()
				}
			}

			drainChannels(ch1, ch2)
			ch1.Close()
			ch2.Close()
		})
	}
}

// bridgePortTestEnv is a bridge with one channel-based port per link address.
type bridgePortTestEnv struct {
	s      *stack.Stack
	bridge *stack.BridgeEndpoint
	nicIDs []tcpip.NICID
	chs    []*channel.Endpoint
}

const (
	bridgePortTestBridgeID   = 20
	bridgePortTestBridgeAddr = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x20")
)

func newBridgePortTestEnv(t *testing.T, linkAddrs ...tcpip.LinkAddress) *bridgePortTestEnv {
	t.Helper()
	env := &bridgePortTestEnv{
		s:      stack.New(stack.Options{}),
		bridge: stack.NewBridgeEndpoint(1500),
	}
	env.bridge.SetLinkAddress(bridgePortTestBridgeAddr)
	if err := env.s.CreateNIC(bridgePortTestBridgeID, env.bridge); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", bridgePortTestBridgeID, err)
	}
	for i, addr := range linkAddrs {
		id := tcpip.NICID(21 + i)
		ch := channel.New(4, header.EthernetMinimumSize, addr)
		if err := env.s.CreateNIC(id, ethernet.New(ch)); err != nil {
			t.Fatalf("s.CreateNIC(%d, _): %s", id, err)
		}
		if err := env.s.SetNICCoordinator(id, bridgePortTestBridgeID); err != nil {
			t.Fatalf("s.SetNICCoordinator(%d, %d): %s", id, bridgePortTestBridgeID, err)
		}
		env.nicIDs = append(env.nicIDs, id)
		env.chs = append(env.chs, ch)
	}
	t.Cleanup(func() {
		drainChannels(env.chs...)
		for _, ch := range env.chs {
			ch.Close()
		}
		env.s.Destroy()
	})
	return env
}

// inject delivers a frame from src to dst on the port at index port.
func (env *bridgePortTestEnv) inject(port int, src, dst tcpip.LinkAddress) {
	pkt := makeEthernetFrame(src, dst)
	env.chs[port].InjectInbound(header.IPv4ProtocolNumber, pkt)
	pkt.DecRef()
}

// forwardedTo returns whether the port at index port sent out a frame, and
// drains everything the port sent.
func (env *bridgePortTestEnv) forwardedTo(port int) bool {
	got := false
	for pkt := env.chs[port].Read(); pkt != nil; pkt = env.chs[port].Read() {
		got = true
		pkt.DecRef()
	}
	return got
}

// TestBridgePortHairpin checks that a frame goes back out of the port it came
// in on only when the port is in hairpin mode, both when it is flooded and
// when its destination was learned on that port.
func TestBridgePortHairpin(t *testing.T) {
	const (
		portAddr1 = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x30")
		portAddr2 = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x31")
		hostA     = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x32")
		hostB     = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x33")
		unknown   = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x34")
	)
	for _, hairpin := range []bool{false, true} {
		name := "off"
		if hairpin {
			name = "on"
		}
		t.Run(name, func(t *testing.T) {
			env := newBridgePortTestEnv(t, portAddr1, portAddr2)
			if hairpin {
				if err := env.s.SetBridgePortFlags(env.nicIDs[0], stack.BridgePortHairpin, 0); err != nil {
					t.Fatalf("SetBridgePortFlags: %s", err)
				}
			}

			// hostA is not known yet, so the frame is flooded. It is learned on
			// port 1 afterwards.
			env.inject(0, hostA, unknown)
			if got := env.forwardedTo(1); !got {
				t.Errorf("flooded frame was not sent out of port 2")
			}
			if got := env.forwardedTo(0); got != hairpin {
				t.Errorf("flooded frame sent back out of the ingress port = %t, want %t", got, hairpin)
			}

			// hostA is on the ingress port, so the frame is not flooded.
			env.inject(0, hostB, hostA)
			if got := env.forwardedTo(0); got != hairpin {
				t.Errorf("frame for an address on the ingress port sent back out of it = %t, want %t", got, hairpin)
			}
			if got := env.forwardedTo(1); got {
				t.Errorf("frame for an address on port 1 was sent out of port 2")
			}

			env.inject(0, hostA, header.EthernetBroadcastAddress)
			if got := env.forwardedTo(1); !got {
				t.Errorf("broadcast frame was not sent out of port 2")
			}
			if got := env.forwardedTo(0); got != hairpin {
				t.Errorf("broadcast frame sent back out of the ingress port = %t, want %t", got, hairpin)
			}
		})
	}
}

// TestBridgePortLearning checks that the source address of a frame is added to
// the forwarding table only when the ingress port has learning enabled.
func TestBridgePortLearning(t *testing.T) {
	const (
		portAddr1 = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x40")
		portAddr2 = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x41")
		portAddr3 = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x42")
		hostX     = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x43")
		hostY     = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x44")
	)
	for _, learning := range []bool{true, false} {
		name := "on"
		if !learning {
			name = "off"
		}
		t.Run(name, func(t *testing.T) {
			env := newBridgePortTestEnv(t, portAddr1, portAddr2, portAddr3)
			if !learning {
				if err := env.s.SetBridgePortFlags(env.nicIDs[1], 0, stack.BridgePortLearning); err != nil {
					t.Fatalf("SetBridgePortFlags: %s", err)
				}
			}

			// Port 2 sees a frame from hostX.
			env.inject(1, hostX, hostY)
			drainChannels(env.chs...)
			entry := env.bridge.FindFDBEntry(hostX)
			if got := entry.PortLinkAddress() == portAddr2; got != learning {
				t.Errorf("hostX learned on port 2 = %t, want %t", got, learning)
			}

			// A frame for hostX is sent only to port 2 if it was learned, and
			// flooded otherwise.
			env.inject(0, hostY, hostX)
			if got := env.forwardedTo(1); !got {
				t.Errorf("frame for hostX was not sent out of port 2")
			}
			if got := env.forwardedTo(2); got == learning {
				t.Errorf("frame for hostX sent out of port 3 = %t, want %t", got, !learning)
			}

			// Other ports keep learning.
			if e := env.bridge.FindFDBEntry(hostY); e.PortLinkAddress() != portAddr1 {
				t.Errorf("hostY learned on %q, want port 1 (%q)", e.PortLinkAddress(), portAddr1)
			}
		})
	}
}

func TestBridgePortFlagsAPI(t *testing.T) {
	const portAddr = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x50")
	env := newBridgePortTestEnv(t, portAddr)
	port := env.nicIDs[0]

	flags, err := env.s.BridgePortFlags(port)
	if err != nil {
		t.Fatalf("BridgePortFlags(%d): %s", port, err)
	}
	if want := stack.BridgePortLearning; flags != want {
		t.Errorf("new port flags = %#x, want %#x", flags, want)
	}

	// One call can set some flags and clear others.
	if err := env.s.SetBridgePortFlags(port, stack.BridgePortHairpin, stack.BridgePortLearning); err != nil {
		t.Fatalf("SetBridgePortFlags(%d): %s", port, err)
	}
	if flags, _ := env.s.BridgePortFlags(port); flags != stack.BridgePortHairpin {
		t.Errorf("flags = %#x, want %#x", flags, stack.BridgePortHairpin)
	}
	// Empty masks change nothing.
	if err := env.s.SetBridgePortFlags(port, 0, 0); err != nil {
		t.Fatalf("SetBridgePortFlags(%d, 0, 0): %s", port, err)
	}
	if flags, _ := env.s.BridgePortFlags(port); flags != stack.BridgePortHairpin {
		t.Errorf("flags = %#x, want %#x", flags, stack.BridgePortHairpin)
	}

	for _, test := range []struct {
		name string
		id   tcpip.NICID
		want tcpip.Error
	}{
		{"unknown NIC", 99, &tcpip.ErrUnknownNICID{}},
		{"the bridge itself", bridgePortTestBridgeID, &tcpip.ErrNotSupported{}},
	} {
		if _, err := env.s.BridgePortFlags(test.id); err == nil || err.String() != test.want.String() {
			t.Errorf("%s: BridgePortFlags() = %v, want %v", test.name, err, test.want)
		}
		if err := env.s.SetBridgePortFlags(test.id, stack.BridgePortHairpin, 0); err == nil || err.String() != test.want.String() {
			t.Errorf("%s: SetBridgePortFlags() = %v, want %v", test.name, err, test.want)
		}
	}
}

func TestMain(m *testing.M) {
	refs.SetLeakMode(refs.LeaksPanic)
	code := m.Run()
	refs.DoLeakCheck()
	os.Exit(code)
}
