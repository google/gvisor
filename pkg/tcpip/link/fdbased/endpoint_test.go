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

// +build linux

package fdbased

import (
	"bytes"
	"fmt"
	"math/rand"
	"reflect"
	"testing"
	"time"
	"unsafe"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	mtu        = 1500
	laddr      = tcpip.LinkAddress("\x11\x22\x33\x44\x55\x66")
	raddr      = tcpip.LinkAddress("\x77\x88\x99\xaa\xbb\xcc")
	proto      = 10
	csumOffset = 48
	gsoMSS     = 500
)

type packetInfo struct {
	Raddr    tcpip.LinkAddress
	Proto    tcpip.NetworkProtocolNumber
	Contents *stack.PacketBuffer
}

type packetContents struct {
	LinkHeader      buffer.View
	NetworkHeader   buffer.View
	TransportHeader buffer.View
	Data            buffer.View
}

func checkPacketInfoEqual(t *testing.T, got, want packetInfo) {
	t.Helper()
	if diff := cmp.Diff(
		want, got,
		cmp.Transformer("ExtractPacketBuffer", func(pk *stack.PacketBuffer) *packetContents {
			if pk == nil {
				return nil
			}
			return &packetContents{
				LinkHeader:      pk.LinkHeader().View(),
				NetworkHeader:   pk.NetworkHeader().View(),
				TransportHeader: pk.TransportHeader().View(),
				Data:            pk.Data().AsRange().ToOwnedView(),
			}
		}),
	); diff != "" {
		t.Errorf("unexpected packetInfo (-want +got):\n%s", diff)
	}
}

type context struct {
	t        *testing.T
	readFDs  []int
	writeFDs []int
	ep       stack.LinkEndpoint
	ch       chan packetInfo
	done     chan struct{}
}

func newContext(t *testing.T, opt *Options) *context {
	firstFDPair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		t.Fatalf("Socketpair failed: %v", err)
	}
	secondFDPair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		t.Fatalf("Socketpair failed: %v", err)
	}

	done := make(chan struct{}, 2)
	opt.ClosedFunc = func(tcpip.Error) {
		done <- struct{}{}
	}

	opt.FDs = []int{firstFDPair[1], secondFDPair[1]}
	ep, err := New(opt)
	if err != nil {
		t.Fatalf("Failed to create FD endpoint: %v", err)
	}

	c := &context{
		t:        t,
		readFDs:  []int{firstFDPair[0], secondFDPair[0]},
		writeFDs: opt.FDs,
		ep:       ep,
		ch:       make(chan packetInfo, 100),
		done:     done,
	}

	ep.Attach(c)

	return c
}

func (c *context) cleanup() {
	for _, fd := range c.readFDs {
		unix.Close(fd)
	}
	<-c.done
	<-c.done
	for _, fd := range c.writeFDs {
		unix.Close(fd)
	}
}

func (c *context) DeliverNetworkPacket(remote tcpip.LinkAddress, local tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	c.ch <- packetInfo{remote, protocol, pkt}
}

func (c *context) DeliverOutboundPacket(remote tcpip.LinkAddress, local tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	panic("unimplemented")
}

func TestNoEthernetProperties(t *testing.T) {
	c := newContext(t, &Options{MTU: mtu})
	defer c.cleanup()

	if want, v := uint16(0), c.ep.MaxHeaderLength(); want != v {
		t.Fatalf("MaxHeaderLength() = %v, want %v", v, want)
	}

	if want, v := uint32(mtu), c.ep.MTU(); want != v {
		t.Fatalf("MTU() = %v, want %v", v, want)
	}
}

func TestEthernetProperties(t *testing.T) {
	c := newContext(t, &Options{EthernetHeader: true, MTU: mtu})
	defer c.cleanup()

	if want, v := uint16(header.EthernetMinimumSize), c.ep.MaxHeaderLength(); want != v {
		t.Fatalf("MaxHeaderLength() = %v, want %v", v, want)
	}

	if want, v := uint32(mtu), c.ep.MTU(); want != v {
		t.Fatalf("MTU() = %v, want %v", v, want)
	}
}

func TestAddress(t *testing.T) {
	addrs := []tcpip.LinkAddress{"", "abc", "def"}
	for _, a := range addrs {
		t.Run(fmt.Sprintf("Address: %q", a), func(t *testing.T) {
			c := newContext(t, &Options{Address: a, MTU: mtu})
			defer c.cleanup()

			if want, v := a, c.ep.LinkAddress(); want != v {
				t.Fatalf("LinkAddress() = %v, want %v", v, want)
			}
		})
	}
}

func testWritePacket(t *testing.T, plen int, eth bool, gsoMaxSize uint32, hash uint32) {
	c := newContext(t, &Options{Address: laddr, MTU: mtu, EthernetHeader: eth, GSOMaxSize: gsoMaxSize})
	defer c.cleanup()

	var r stack.RouteInfo
	r.RemoteLinkAddress = raddr

	// Build payload.
	payload := buffer.NewView(plen)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand.Read(payload): %s", err)
	}

	// Build packet buffer.
	const netHdrLen = 100
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(c.ep.MaxHeaderLength()) + netHdrLen,
		Data:               payload.ToVectorisedView(),
	})
	pkt.Hash = hash

	// Build header.
	b := pkt.NetworkHeader().Push(netHdrLen)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read(b): %s", err)
	}

	// Write.
	want := append(append(buffer.View(nil), b...), payload...)
	var gso stack.GSO
	if gsoMaxSize != 0 {
		gso = stack.GSO{
			Type:       stack.GSOTCPv6,
			NeedsCsum:  true,
			CsumOffset: csumOffset,
			MSS:        gsoMSS,
			L3HdrLen:   header.IPv4MaximumHeaderSize,
		}
	}
	if err := c.ep.WritePacket(r, gso, proto, pkt); err != nil {
		t.Fatalf("WritePacket failed: %v", err)
	}

	// Read from the corresponding FD, then compare with what we wrote.
	b = make([]byte, mtu)
	fd := c.readFDs[hash%uint32(len(c.readFDs))]
	n, err := unix.Read(fd, b)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	b = b[:n]
	if gsoMaxSize != 0 {
		vnetHdr := *(*virtioNetHdr)(unsafe.Pointer(&b[0]))
		if vnetHdr.flags&_VIRTIO_NET_HDR_F_NEEDS_CSUM == 0 {
			t.Fatalf("virtioNetHdr.flags %v  doesn't contain %v", vnetHdr.flags, _VIRTIO_NET_HDR_F_NEEDS_CSUM)
		}
		csumStart := header.EthernetMinimumSize + gso.L3HdrLen
		if vnetHdr.csumStart != csumStart {
			t.Fatalf("vnetHdr.csumStart = %v, want %v", vnetHdr.csumStart, csumStart)
		}
		if vnetHdr.csumOffset != csumOffset {
			t.Fatalf("vnetHdr.csumOffset = %v, want %v", vnetHdr.csumOffset, csumOffset)
		}
		gsoType := uint8(0)
		if int(gso.MSS) < plen {
			gsoType = _VIRTIO_NET_HDR_GSO_TCPV6
		}
		if vnetHdr.gsoType != gsoType {
			t.Fatalf("vnetHdr.gsoType = %v, want %v", vnetHdr.gsoType, gsoType)
		}
		b = b[virtioNetHdrSize:]
	}
	if eth {
		h := header.Ethernet(b)
		b = b[header.EthernetMinimumSize:]

		if a := h.SourceAddress(); a != laddr {
			t.Fatalf("SourceAddress() = %v, want %v", a, laddr)
		}

		if a := h.DestinationAddress(); a != raddr {
			t.Fatalf("DestinationAddress() = %v, want %v", a, raddr)
		}

		if et := h.Type(); et != proto {
			t.Fatalf("Type() = %v, want %v", et, proto)
		}
	}
	if len(b) != len(want) {
		t.Fatalf("Read returned %v bytes, want %v", len(b), len(want))
	}
	if !bytes.Equal(b, want) {
		t.Fatalf("Read returned %x, want %x", b, want)
	}
}

func TestWritePacket(t *testing.T) {
	lengths := []int{0, 100, 1000}
	eths := []bool{true, false}
	gsos := []uint32{0, 32768}

	for _, eth := range eths {
		for _, plen := range lengths {
			for _, gso := range gsos {
				t.Run(
					fmt.Sprintf("Eth=%v,PayloadLen=%v,GSOMaxSize=%v", eth, plen, gso),
					func(t *testing.T) {
						testWritePacket(t, plen, eth, gso, 0)
					},
				)
			}
		}
	}
}

func TestHashedWritePacket(t *testing.T) {
	lengths := []int{0, 100, 1000}
	eths := []bool{true, false}
	gsos := []uint32{0, 32768}
	hashes := []uint32{0, 1}
	for _, eth := range eths {
		for _, plen := range lengths {
			for _, gso := range gsos {
				for _, hash := range hashes {
					t.Run(
						fmt.Sprintf("Eth=%v,PayloadLen=%v,GSOMaxSize=%v,Hash=%d", eth, plen, gso, hash),
						func(t *testing.T) {
							testWritePacket(t, plen, eth, gso, hash)
						},
					)
				}
			}
		}
	}
}

func TestPreserveSrcAddress(t *testing.T) {
	baddr := tcpip.LinkAddress("\xcc\xbb\xaa\x77\x88\x99")

	c := newContext(t, &Options{Address: laddr, MTU: mtu, EthernetHeader: true})
	defer c.cleanup()

	// Set LocalLinkAddress in route to the value of the bridged address.
	var r stack.RouteInfo
	r.LocalLinkAddress = baddr
	r.RemoteLinkAddress = raddr

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		// WritePacket panics given a prependable with anything less than
		// the minimum size of the ethernet header.
		// TODO(b/153685824): Figure out if this should use c.ep.MaxHeaderLength().
		ReserveHeaderBytes: header.EthernetMinimumSize,
		Data:               buffer.VectorisedView{},
	})
	if err := c.ep.WritePacket(r, stack.GSO{}, proto, pkt); err != nil {
		t.Fatalf("WritePacket failed: %v", err)
	}

	// Read from the FD, then compare with what we wrote.
	b := make([]byte, mtu)
	n, err := unix.Read(c.readFDs[0], b)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	b = b[:n]
	h := header.Ethernet(b)

	if a := h.SourceAddress(); a != baddr {
		t.Fatalf("SourceAddress() = %v, want %v", a, baddr)
	}
}

func TestDeliverPacket(t *testing.T) {
	lengths := []int{100, 1000}
	eths := []bool{true, false}

	for _, eth := range eths {
		for _, plen := range lengths {
			t.Run(fmt.Sprintf("Eth=%v,PayloadLen=%v", eth, plen), func(t *testing.T) {
				c := newContext(t, &Options{Address: laddr, MTU: mtu, EthernetHeader: eth})
				defer c.cleanup()

				// Build packet.
				all := make([]byte, plen)
				if _, err := rand.Read(all); err != nil {
					t.Fatalf("rand.Read(all): %s", err)
				}
				// Make it look like an IPv4 packet.
				all[0] = 0x40

				wantPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
					ReserveHeaderBytes: header.EthernetMinimumSize,
					Data:               buffer.NewViewFromBytes(all).ToVectorisedView(),
				})
				if eth {
					hdr := header.Ethernet(wantPkt.LinkHeader().Push(header.EthernetMinimumSize))
					hdr.Encode(&header.EthernetFields{
						SrcAddr: raddr,
						DstAddr: laddr,
						Type:    proto,
					})
					all = append(hdr, all...)
				}

				// Write packet via the file descriptor.
				if _, err := unix.Write(c.readFDs[0], all); err != nil {
					t.Fatalf("Write failed: %v", err)
				}

				// Receive packet through the endpoint.
				select {
				case pi := <-c.ch:
					want := packetInfo{
						Raddr:    raddr,
						Proto:    proto,
						Contents: wantPkt,
					}
					if !eth {
						want.Proto = header.IPv4ProtocolNumber
						want.Raddr = ""
					}
					checkPacketInfoEqual(t, pi, want)
				case <-time.After(10 * time.Second):
					t.Fatalf("Timed out waiting for packet")
				}
			})
		}
	}
}

func TestBufConfigMaxLength(t *testing.T) {
	got := 0
	for _, i := range BufConfig {
		got += i
	}
	want := header.MaxIPPacketSize // maximum TCP packet size
	if got < want {
		t.Errorf("total buffer size is invalid: got %d, want >= %d", got, want)
	}
}

func TestBufConfigFirst(t *testing.T) {
	// The stack assumes that the TCP/IP header is enterily contained in the first view.
	// Therefore, the first view needs to be large enough to contain the maximum TCP/IP
	// header, which is 120 bytes (60 bytes for IP + 60 bytes for TCP).
	want := 120
	got := BufConfig[0]
	if got < want {
		t.Errorf("first view has an invalid size: got %d, want >= %d", got, want)
	}
}

var capLengthTestCases = []struct {
	comment     string
	config      []int
	n           int
	wantUsed    int
	wantLengths []int
}{
	{
		comment:     "Single slice",
		config:      []int{2},
		n:           1,
		wantUsed:    1,
		wantLengths: []int{1},
	},
	{
		comment:     "Multiple slices",
		config:      []int{1, 2},
		n:           2,
		wantUsed:    2,
		wantLengths: []int{1, 1},
	},
	{
		comment:     "Entire buffer",
		config:      []int{1, 2},
		n:           3,
		wantUsed:    2,
		wantLengths: []int{1, 2},
	},
	{
		comment:     "Entire buffer but not on the last slice",
		config:      []int{1, 2, 3},
		n:           3,
		wantUsed:    2,
		wantLengths: []int{1, 2},
	},
}

func TestIovecBuffer(t *testing.T) {
	for _, c := range capLengthTestCases {
		t.Run(c.comment, func(t *testing.T) {
			b := newIovecBuffer(c.config, false /* skipsVnetHdr */)

			// Test initial allocation.
			iovecs := b.nextIovecs()
			if got, want := len(iovecs), len(c.config); got != want {
				t.Fatalf("len(iovecs) = %d, want %d", got, want)
			}

			// Make a copy as iovecs points to internal slice. We will need this state
			// later.
			oldIovecs := append([]unix.Iovec(nil), iovecs...)

			// Test the views that get pulled.
			vv := b.pullViews(c.n)
			var lengths []int
			for _, v := range vv.Views() {
				lengths = append(lengths, len(v))
			}
			if !reflect.DeepEqual(lengths, c.wantLengths) {
				t.Errorf("Pulled view lengths = %v, want %v", lengths, c.wantLengths)
			}

			// Test that new views get reallocated.
			for i, newIov := range b.nextIovecs() {
				if i < c.wantUsed {
					if newIov.Base == oldIovecs[i].Base {
						t.Errorf("b.views[%d] should have been reallocated", i)
					}
				} else {
					if newIov.Base != oldIovecs[i].Base {
						t.Errorf("b.views[%d] should not have been reallocated", i)
					}
				}
			}
		})
	}
}

func TestIovecBufferSkipVnetHdr(t *testing.T) {
	for _, test := range []struct {
		desc    string
		readN   int
		wantLen int
	}{
		{
			desc:    "nothing read",
			readN:   0,
			wantLen: 0,
		},
		{
			desc:    "smaller than vnet header",
			readN:   virtioNetHdrSize - 1,
			wantLen: 0,
		},
		{
			desc:    "header skipped",
			readN:   virtioNetHdrSize + 100,
			wantLen: 100,
		},
	} {
		t.Run(test.desc, func(t *testing.T) {
			b := newIovecBuffer([]int{10, 20, 50, 50}, true)
			// Pretend a read happend.
			b.nextIovecs()
			vv := b.pullViews(test.readN)
			if got, want := vv.Size(), test.wantLen; got != want {
				t.Errorf("b.pullView(%d).Size() = %d; want %d", test.readN, got, want)
			}
			if got, want := len(vv.ToOwnedView()), test.wantLen; got != want {
				t.Errorf("b.pullView(%d).ToOwnedView() has length %d; want %d", test.readN, got, want)
			}
		})
	}
}

// fakeNetworkDispatcher delivers packets to pkts.
type fakeNetworkDispatcher struct {
	pkts []*stack.PacketBuffer
}

func (d *fakeNetworkDispatcher) DeliverNetworkPacket(remote, local tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	d.pkts = append(d.pkts, pkt)
}

func (d *fakeNetworkDispatcher) DeliverOutboundPacket(remote, local tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	panic("unimplemented")
}

func TestDispatchPacketFormat(t *testing.T) {
	for _, test := range []struct {
		name          string
		newDispatcher func(fd int, e *endpoint) (linkDispatcher, error)
	}{
		{
			name:          "readVDispatcher",
			newDispatcher: newReadVDispatcher,
		},
		{
			name:          "recvMMsgDispatcher",
			newDispatcher: newRecvMMsgDispatcher,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			// Create a socket pair to send/recv.
			fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(fds[0])
			defer unix.Close(fds[1])

			data := []byte{
				// Ethernet header.
				1, 2, 3, 4, 5, 60,
				1, 2, 3, 4, 5, 61,
				8, 0,
				// Mock network header.
				40, 41, 42, 43,
			}
			err = unix.Sendmsg(fds[1], data, nil, nil, 0)
			if err != nil {
				t.Fatal(err)
			}

			// Create and run dispatcher once.
			sink := &fakeNetworkDispatcher{}
			d, err := test.newDispatcher(fds[0], &endpoint{
				hdrSize:    header.EthernetMinimumSize,
				dispatcher: sink,
			})
			if err != nil {
				t.Fatal(err)
			}
			if ok, err := d.dispatch(); !ok || err != nil {
				t.Fatalf("d.dispatch() = %v, %v", ok, err)
			}

			// Verify packet.
			if got, want := len(sink.pkts), 1; got != want {
				t.Fatalf("len(sink.pkts) = %d, want %d", got, want)
			}
			pkt := sink.pkts[0]
			if got, want := pkt.LinkHeader().View().Size(), header.EthernetMinimumSize; got != want {
				t.Errorf("pkt.LinkHeader().View().Size() = %d, want %d", got, want)
			}
			if got, want := pkt.Data().Size(), 4; got != want {
				t.Errorf("pkt.Data().Size() = %d, want %d", got, want)
			}
		})
	}
}
