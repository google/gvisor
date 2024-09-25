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
		localLinkAddr  = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x06")
		remoteLinkAddr = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x07")
		bridgeLinkAddr = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x08")

		netProto = 55
		nicID    = 5
		bridgeID = 6
	)

	c := channel.New(1, header.EthernetMinimumSize, localLinkAddr)

	s := stack.New(stack.Options{})
	if err := s.CreateNIC(nicID, ethernet.New(c)); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", nicID, err)
	}
	bridgeEndpoint := stack.NewBridgeEndpoint(1500)
	bridgeEndpoint.SetLinkAddress(bridgeLinkAddr)
	if err := s.CreateNIC(bridgeID, bridgeEndpoint); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", nicID, err)
	}
	if err := s.SetNICCoordinator(nicID, bridgeID); err != nil {
		t.Fatalf("s.SetNICCoordinator")
	}

	if err := s.WritePacketToRemote(bridgeID, remoteLinkAddr, netProto, buffer.Buffer{}); err != nil {
		t.Fatalf("s.WritePacketToRemote(%d, %s, _): %s", bridgeID, remoteLinkAddr, err)
	}
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

type testNotification struct {
	ch chan bool
}

func (n *testNotification) WriteNotify() {
	n.ch <- true
}

func TestWritePacketBetweenDevices(t *testing.T) {
	const (
		localLinkAddr  = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x06")
		remoteLinkAddr = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x07")
		bridgeLinkAddr = tcpip.LinkAddress("\x02\x02\x03\x04\x05\x08")

		netProto = 55
		nicID    = 5
		vethID   = 7
		bridgeID = 6
	)
	veth1, veth2 := veth.NewPair(1500)
	veth2.SetLinkAddress(localLinkAddr)
	c := channel.New(1, header.EthernetMinimumSize, localLinkAddr)
	c.SetLinkAddress(remoteLinkAddr)

	for _, addFDB := range []bool{true, false} {
		bridgeEndpoint := stack.NewBridgeEndpoint(1500)
		bridgeEndpoint.SetLinkAddress(bridgeLinkAddr)
		s := stack.New(stack.Options{})
		secondStack := stack.New(stack.Options{})
		if err := s.CreateNIC(bridgeID, bridgeEndpoint); err != nil {
			t.Fatalf("s.CreateNIC(%d, _): %s", bridgeID, err)
		}
		if err := s.CreateNIC(nicID, ethernet.New(c)); err != nil {
			t.Fatalf("s.CreateNIC(%d, _): %s", nicID, err)
		}
		if err := s.SetNICCoordinator(nicID, bridgeID); err != nil {
			t.Fatalf("s.SetNICCoordinator(%d, %d)", nicID, bridgeID)
		}
		if err := s.CreateNIC(vethID, ethernet.New(veth1)); err != nil {
			t.Fatalf("s.CreateNIC(%d, _): %s", vethID, err)
		}
		if err := s.SetNICCoordinator(vethID, bridgeID); err != nil {
			t.Fatalf("s.SetNICCoordinator")
		}
		if err := secondStack.CreateNIC(vethID, ethernet.New(veth2)); err != nil {
			t.Fatalf("s.CreateNIC(%d, _): %s", vethID, err)
		}
		if addFDB {
			if err := bridgeEndpoint.AddFDBEntry(veth1.LinkAddress(), nicID, 0); err != nil {
				t.Fatalf("bridgeEndpoint.AddFDBEntry(%s, %d, _): %s", veth1.LinkAddress(), nicID, err)
			}
		}

		n := &testNotification{ch: make(chan bool, 1)}
		c.AddNotify(n)
		if err := secondStack.WritePacketToRemote(vethID, remoteLinkAddr, netProto, buffer.Buffer{}); err != nil {
			t.Fatalf("s.WritePacketToRemote(%d, %s, _): %s", bridgeID, remoteLinkAddr, err)
		}
		<-n.ch
		pkt := c.Read()
		if pkt == nil {
			t.Fatal("expected to read a packet")
		}

		pkt.LinkHeader().Consume(header.EthernetMinimumSize)
		eth := header.Ethernet(pkt.LinkHeader().Slice())
		pkt.DecRef()
		if got := eth.SourceAddress(); got != localLinkAddr {
			t.Errorf("got eth.SourceAddress() = %s, want = %s", got, localLinkAddr)
		}
		if got := eth.DestinationAddress(); got != remoteLinkAddr {
			t.Errorf("got eth.DestinationAddress() = %s, want = %s", got, remoteLinkAddr)
		}
		if got := eth.Type(); got != netProto {
			t.Errorf("got eth.Type() = %d, want = %d", got, netProto)
		}
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

func TestMain(m *testing.M) {
	refs.SetLeakMode(refs.LeaksPanic)
	code := m.Run()
	refs.DoLeakCheck()
	os.Exit(code)
}
