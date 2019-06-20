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
	"syscall"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/rawfile"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// BufConfig defines the shape of the vectorised view used to read packets from the NIC.
var BufConfig = []int{128, 256, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768}

// readVDispatcher uses readv() system call to read inbound packets and
// dispatches them.
type readVDispatcher struct {
	// fd is the file descriptor used to send and receive packets.
	fd int

	// e is the endpoint this dispatcher is attached to.
	e *endpoint

	// views are the actual buffers that hold the packet contents.
	views []buffer.View

	// iovecs are initialized with base pointers/len of the corresponding
	// entries in the views defined above, except when GSO is enabled then
	// the first iovec points to a buffer for the vnet header which is
	// stripped before the views are passed up the stack for further
	// processing.
	iovecs []syscall.Iovec
}

func newReadVDispatcher(fd int, e *endpoint) (linkDispatcher, error) {
	d := &readVDispatcher{fd: fd, e: e}
	d.views = make([]buffer.View, len(BufConfig))
	iovLen := len(BufConfig)
	if d.e.Capabilities()&stack.CapabilityGSO != 0 {
		iovLen++
	}
	d.iovecs = make([]syscall.Iovec, iovLen)
	return d, nil
}

func (d *readVDispatcher) allocateViews(bufConfig []int) {
	var vnetHdr [virtioNetHdrSize]byte
	vnetHdrOff := 0
	if d.e.Capabilities()&stack.CapabilityGSO != 0 {
		// The kernel adds virtioNetHdr before each packet, but
		// we don't use it, so so we allocate a buffer for it,
		// add it in iovecs but don't add it in a view.
		d.iovecs[0] = syscall.Iovec{
			Base: &vnetHdr[0],
			Len:  uint64(virtioNetHdrSize),
		}
		vnetHdrOff++
	}
	for i := 0; i < len(bufConfig); i++ {
		if d.views[i] != nil {
			break
		}
		b := buffer.NewView(bufConfig[i])
		d.views[i] = b
		d.iovecs[i+vnetHdrOff] = syscall.Iovec{
			Base: &b[0],
			Len:  uint64(len(b)),
		}
	}
}

func (d *readVDispatcher) capViews(n int, buffers []int) int {
	c := 0
	for i, s := range buffers {
		c += s
		if c >= n {
			d.views[i].CapLength(s - (c - n))
			return i + 1
		}
	}
	return len(buffers)
}

// dispatch reads one packet from the file descriptor and dispatches it.
func (d *readVDispatcher) dispatch() (bool, *tcpip.Error) {
	d.allocateViews(BufConfig)

	n, err := rawfile.BlockingReadv(d.fd, d.iovecs)
	if err != nil {
		return false, err
	}
	if d.e.Capabilities()&stack.CapabilityGSO != 0 {
		// Skip virtioNetHdr which is added before each packet, it
		// isn't used and it isn't in a view.
		n -= virtioNetHdrSize
	}
	if n <= d.e.hdrSize {
		return false, nil
	}

	var (
		p             tcpip.NetworkProtocolNumber
		remote, local tcpip.LinkAddress
	)
	if d.e.hdrSize > 0 {
		eth := header.Ethernet(d.views[0])
		p = eth.Type()
		remote = eth.SourceAddress()
		local = eth.DestinationAddress()
	} else {
		// We don't get any indication of what the packet is, so try to guess
		// if it's an IPv4 or IPv6 packet.
		switch header.IPVersion(d.views[0]) {
		case header.IPv4Version:
			p = header.IPv4ProtocolNumber
		case header.IPv6Version:
			p = header.IPv6ProtocolNumber
		default:
			return true, nil
		}
	}

	used := d.capViews(n, BufConfig)
	vv := buffer.NewVectorisedView(n, d.views[:used])
	vv.TrimFront(d.e.hdrSize)

	d.e.dispatcher.DeliverNetworkPacket(d.e, remote, local, p, vv)

	// Prepare e.views for another packet: release used views.
	for i := 0; i < used; i++ {
		d.views[i] = nil
	}

	return true, nil
}

// recvMMsgDispatcher uses the recvmmsg system call to read inbound packets and
// dispatches them.
type recvMMsgDispatcher struct {
	// fd is the file descriptor used to send and receive packets.
	fd int

	// e is the endpoint this dispatcher is attached to.
	e *endpoint

	// views is an array of array of buffers that contain packet contents.
	views [][]buffer.View

	// iovecs is an array of array of iovec records where each iovec base
	// pointer and length are initialzed to the corresponding view above,
	// except when GSO is neabled then the first iovec in each array of
	// iovecs points to a buffer for the vnet header which is stripped
	// before the views are passed up the stack for further processing.
	iovecs [][]syscall.Iovec

	// msgHdrs is an array of MMsgHdr objects where each MMsghdr is used to
	// reference an array of iovecs in the iovecs field defined above.  This
	// array is passed as the parameter to recvmmsg call to retrieve
	// potentially more than 1 packet per syscall.
	msgHdrs []rawfile.MMsgHdr
}

const (
	// MaxMsgsPerRecv is the maximum number of packets we want to retrieve
	// in a single RecvMMsg call.
	MaxMsgsPerRecv = 8
)

func newRecvMMsgDispatcher(fd int, e *endpoint) (linkDispatcher, error) {
	d := &recvMMsgDispatcher{
		fd: fd,
		e:  e,
	}
	d.views = make([][]buffer.View, MaxMsgsPerRecv)
	for i := range d.views {
		d.views[i] = make([]buffer.View, len(BufConfig))
	}
	d.iovecs = make([][]syscall.Iovec, MaxMsgsPerRecv)
	iovLen := len(BufConfig)
	if d.e.Capabilities()&stack.CapabilityGSO != 0 {
		// virtioNetHdr is prepended before each packet.
		iovLen++
	}
	for i := range d.iovecs {
		d.iovecs[i] = make([]syscall.Iovec, iovLen)
	}
	d.msgHdrs = make([]rawfile.MMsgHdr, MaxMsgsPerRecv)
	for i := range d.msgHdrs {
		d.msgHdrs[i].Msg.Iov = &d.iovecs[i][0]
		d.msgHdrs[i].Msg.Iovlen = uint64(iovLen)
	}
	return d, nil
}

func (d *recvMMsgDispatcher) capViews(k, n int, buffers []int) int {
	c := 0
	for i, s := range buffers {
		c += s
		if c >= n {
			d.views[k][i].CapLength(s - (c - n))
			return i + 1
		}
	}
	return len(buffers)
}

func (d *recvMMsgDispatcher) allocateViews(bufConfig []int) {
	for k := 0; k < len(d.views); k++ {
		var vnetHdr [virtioNetHdrSize]byte
		vnetHdrOff := 0
		if d.e.Capabilities()&stack.CapabilityGSO != 0 {
			// The kernel adds virtioNetHdr before each packet, but
			// we don't use it, so so we allocate a buffer for it,
			// add it in iovecs but don't add it in a view.
			d.iovecs[k][0] = syscall.Iovec{
				Base: &vnetHdr[0],
				Len:  uint64(virtioNetHdrSize),
			}
			vnetHdrOff++
		}
		for i := 0; i < len(bufConfig); i++ {
			if d.views[k][i] != nil {
				break
			}
			b := buffer.NewView(bufConfig[i])
			d.views[k][i] = b
			d.iovecs[k][i+vnetHdrOff] = syscall.Iovec{
				Base: &b[0],
				Len:  uint64(len(b)),
			}
		}
	}
}

// recvMMsgDispatch reads more than one packet at a time from the file
// descriptor and dispatches it.
func (d *recvMMsgDispatcher) dispatch() (bool, *tcpip.Error) {
	d.allocateViews(BufConfig)

	nMsgs, err := rawfile.BlockingRecvMMsg(d.fd, d.msgHdrs)
	if err != nil {
		return false, err
	}
	// Process each of received packets.
	for k := 0; k < nMsgs; k++ {
		n := int(d.msgHdrs[k].Len)
		if d.e.Capabilities()&stack.CapabilityGSO != 0 {
			n -= virtioNetHdrSize
		}
		if n <= d.e.hdrSize {
			return false, nil
		}

		var (
			p             tcpip.NetworkProtocolNumber
			remote, local tcpip.LinkAddress
		)
		if d.e.hdrSize > 0 {
			eth := header.Ethernet(d.views[k][0])
			p = eth.Type()
			remote = eth.SourceAddress()
			local = eth.DestinationAddress()
		} else {
			// We don't get any indication of what the packet is, so try to guess
			// if it's an IPv4 or IPv6 packet.
			switch header.IPVersion(d.views[k][0]) {
			case header.IPv4Version:
				p = header.IPv4ProtocolNumber
			case header.IPv6Version:
				p = header.IPv6ProtocolNumber
			default:
				return true, nil
			}
		}

		used := d.capViews(k, int(n), BufConfig)
		vv := buffer.NewVectorisedView(int(n), d.views[k][:used])
		vv.TrimFront(d.e.hdrSize)
		d.e.dispatcher.DeliverNetworkPacket(d.e, remote, local, p, vv)

		// Prepare e.views for another packet: release used views.
		for i := 0; i < used; i++ {
			d.views[k][i] = nil
		}
	}

	for k := 0; k < nMsgs; k++ {
		d.msgHdrs[k].Len = 0
	}

	return true, nil
}
