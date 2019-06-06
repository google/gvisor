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
	"syscall"
	"testing"
	"time"
	"unsafe"

	"gvisor.googlesource.com/gvisor/pkg/tcpip"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/buffer"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/header"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/link/rawfile"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/stack"
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
	raddr    tcpip.LinkAddress
	proto    tcpip.NetworkProtocolNumber
	contents buffer.View
}

type context struct {
	t    *testing.T
	fds  [2]int
	ep   stack.LinkEndpoint
	ch   chan packetInfo
	done chan struct{}
}

func newContext(t *testing.T, opt *Options) *context {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET, 0)
	if err != nil {
		t.Fatalf("Socketpair failed: %v", err)
	}

	done := make(chan struct{}, 1)
	opt.ClosedFunc = func(*tcpip.Error) {
		done <- struct{}{}
	}

	opt.FDs = []int{fds[1]}
	epID, err := New(opt)
	if err != nil {
		t.Fatalf("Failed to create FD endpoint: %v", err)
	}
	ep := stack.FindLinkEndpoint(epID).(*endpoint)

	c := &context{
		t:    t,
		fds:  fds,
		ep:   ep,
		ch:   make(chan packetInfo, 100),
		done: done,
	}

	ep.Attach(c)

	return c
}

func (c *context) cleanup() {
	syscall.Close(c.fds[0])
	<-c.done
	syscall.Close(c.fds[1])
}

func (c *context) DeliverNetworkPacket(linkEP stack.LinkEndpoint, remote tcpip.LinkAddress, local tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, vv buffer.VectorisedView) {
	c.ch <- packetInfo{remote, protocol, vv.ToView()}
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

func testWritePacket(t *testing.T, plen int, eth bool, gsoMaxSize uint32) {
	c := newContext(t, &Options{Address: laddr, MTU: mtu, EthernetHeader: eth, GSOMaxSize: gsoMaxSize})
	defer c.cleanup()

	r := &stack.Route{
		RemoteLinkAddress: raddr,
	}

	// Build header.
	hdr := buffer.NewPrependable(int(c.ep.MaxHeaderLength()) + 100)
	b := hdr.Prepend(100)
	for i := range b {
		b[i] = uint8(rand.Intn(256))
	}

	// Build payload and write.
	payload := make(buffer.View, plen)
	for i := range payload {
		payload[i] = uint8(rand.Intn(256))
	}
	want := append(hdr.View(), payload...)
	var gso *stack.GSO
	if gsoMaxSize != 0 {
		gso = &stack.GSO{
			Type:       stack.GSOTCPv6,
			NeedsCsum:  true,
			CsumOffset: csumOffset,
			MSS:        gsoMSS,
			MaxSize:    gsoMaxSize,
			L3HdrLen:   header.IPv4MaximumHeaderSize,
		}
	}
	if err := c.ep.WritePacket(r, gso, hdr, payload.ToVectorisedView(), proto); err != nil {
		t.Fatalf("WritePacket failed: %v", err)
	}

	// Read from fd, then compare with what we wrote.
	b = make([]byte, mtu)
	n, err := syscall.Read(c.fds[0], b)
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
						testWritePacket(t, plen, eth, gso)
					},
				)
			}
		}
	}
}

func TestPreserveSrcAddress(t *testing.T) {
	baddr := tcpip.LinkAddress("\xcc\xbb\xaa\x77\x88\x99")

	c := newContext(t, &Options{Address: laddr, MTU: mtu, EthernetHeader: true})
	defer c.cleanup()

	// Set LocalLinkAddress in route to the value of the bridged address.
	r := &stack.Route{
		RemoteLinkAddress: raddr,
		LocalLinkAddress:  baddr,
	}

	// WritePacket panics given a prependable with anything less than
	// the minimum size of the ethernet header.
	hdr := buffer.NewPrependable(header.EthernetMinimumSize)
	if err := c.ep.WritePacket(r, nil /* gso */, hdr, buffer.VectorisedView{}, proto); err != nil {
		t.Fatalf("WritePacket failed: %v", err)
	}

	// Read from the FD, then compare with what we wrote.
	b := make([]byte, mtu)
	n, err := syscall.Read(c.fds[0], b)
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
				b := make([]byte, plen)
				all := b
				for i := range b {
					b[i] = uint8(rand.Intn(256))
				}

				if !eth {
					// So that it looks like an IPv4 packet.
					b[0] = 0x40
				} else {
					hdr := make(header.Ethernet, header.EthernetMinimumSize)
					hdr.Encode(&header.EthernetFields{
						SrcAddr: raddr,
						DstAddr: laddr,
						Type:    proto,
					})
					all = append(hdr, b...)
				}

				// Write packet via the file descriptor.
				if _, err := syscall.Write(c.fds[0], all); err != nil {
					t.Fatalf("Write failed: %v", err)
				}

				// Receive packet through the endpoint.
				select {
				case pi := <-c.ch:
					want := packetInfo{
						raddr:    raddr,
						proto:    proto,
						contents: b,
					}
					if !eth {
						want.proto = header.IPv4ProtocolNumber
						want.raddr = ""
					}
					if !reflect.DeepEqual(want, pi) {
						t.Fatalf("Unexpected received packet: %+v, want %+v", pi, want)
					}
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
		wantLengths: []int{1, 2, 3},
	},
}

func TestReadVDispatcherCapLength(t *testing.T) {
	for _, c := range capLengthTestCases {
		// fd does not matter for this test.
		d := readVDispatcher{fd: -1, e: &endpoint{}}
		d.views = make([]buffer.View, len(c.config))
		d.iovecs = make([]syscall.Iovec, len(c.config))
		d.allocateViews(c.config)

		used := d.capViews(c.n, c.config)
		if used != c.wantUsed {
			t.Errorf("Test %q failed when calling capViews(%d, %v). Got %d. Want %d", c.comment, c.n, c.config, used, c.wantUsed)
		}
		lengths := make([]int, len(d.views))
		for i, v := range d.views {
			lengths[i] = len(v)
		}
		if !reflect.DeepEqual(lengths, c.wantLengths) {
			t.Errorf("Test %q failed when calling capViews(%d, %v). Got %v. Want %v", c.comment, c.n, c.config, lengths, c.wantLengths)
		}
	}
}

func TestRecvMMsgDispatcherCapLength(t *testing.T) {
	for _, c := range capLengthTestCases {
		d := recvMMsgDispatcher{
			fd:      -1, // fd does not matter for this test.
			e:       &endpoint{},
			views:   make([][]buffer.View, 1),
			iovecs:  make([][]syscall.Iovec, 1),
			msgHdrs: make([]rawfile.MMsgHdr, 1),
		}

		for i, _ := range d.views {
			d.views[i] = make([]buffer.View, len(c.config))
		}
		for i := range d.iovecs {
			d.iovecs[i] = make([]syscall.Iovec, len(c.config))
		}
		for k, msgHdr := range d.msgHdrs {
			msgHdr.Msg.Iov = &d.iovecs[k][0]
			msgHdr.Msg.Iovlen = uint64(len(c.config))
		}

		d.allocateViews(c.config)

		used := d.capViews(0, c.n, c.config)
		if used != c.wantUsed {
			t.Errorf("Test %q failed when calling capViews(%d, %v). Got %d. Want %d", c.comment, c.n, c.config, used, c.wantUsed)
		}
		lengths := make([]int, len(d.views[0]))
		for i, v := range d.views[0] {
			lengths[i] = len(v)
		}
		if !reflect.DeepEqual(lengths, c.wantLengths) {
			t.Errorf("Test %q failed when calling capViews(%d, %v). Got %v. Want %v", c.comment, c.n, c.config, lengths, c.wantLengths)
		}

	}
}
