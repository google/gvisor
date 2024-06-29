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

//go:build linux
// +build linux

package fdbased

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/rawfile"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/stopfd"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/stack/gro"
)

// BufConfig defines the shape of the buffer used to read packets from the NIC.
var BufConfig = []int{128, 256, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768}

type iovecBuffer struct {
	// buffer is the actual buffer that holds the packet contents. Some contents
	// are reused across calls to pullBuffer if number of requested bytes is
	// smaller than the number of bytes allocated in the buffer.
	views []*buffer.View

	// iovecs are initialized with base pointers/len of the corresponding
	// entries in the views defined above, except when GSO is enabled
	// (skipsVnetHdr) then the first iovec points to a buffer for the vnet header
	// which is stripped before the views are passed up the stack for further
	// processing.
	iovecs []unix.Iovec

	// sizes is an array of buffer sizes for the underlying views. sizes is
	// immutable.
	sizes []int

	// skipsVnetHdr is true if virtioNetHdr is to skipped.
	skipsVnetHdr bool

	// pulledIndex is the index of the last []byte buffer pulled from the
	// underlying buffer storage during a call to pullBuffers. It is -1
	// if no buffer is pulled.
	pulledIndex int
}

func newIovecBuffer(sizes []int, skipsVnetHdr bool) *iovecBuffer {
	b := &iovecBuffer{
		views:        make([]*buffer.View, len(sizes)),
		sizes:        sizes,
		skipsVnetHdr: skipsVnetHdr,
	}
	niov := len(b.views)
	if b.skipsVnetHdr {
		niov++
	}
	b.iovecs = make([]unix.Iovec, niov)
	return b
}

func (b *iovecBuffer) nextIovecs() []unix.Iovec {
	vnetHdrOff := 0
	if b.skipsVnetHdr {
		var vnetHdr [virtioNetHdrSize]byte
		// The kernel adds virtioNetHdr before each packet, but
		// we don't use it, so we allocate a buffer for it,
		// add it in iovecs but don't add it in a view.
		b.iovecs[0] = unix.Iovec{Base: &vnetHdr[0]}
		b.iovecs[0].SetLen(virtioNetHdrSize)
		vnetHdrOff++
	}

	for i := range b.views {
		if b.views[i] != nil {
			break
		}
		v := buffer.NewViewSize(b.sizes[i])
		b.views[i] = v
		b.iovecs[i+vnetHdrOff] = unix.Iovec{Base: v.BasePtr()}
		b.iovecs[i+vnetHdrOff].SetLen(v.Size())
	}
	return b.iovecs
}

// pullBuffer extracts the enough underlying storage from b.buffer to hold n
// bytes. It removes this storage from b.buffer, returns a new buffer
// that holds the storage, and updates pulledIndex to indicate which part
// of b.buffer's storage must be reallocated during the next call to
// nextIovecs.
func (b *iovecBuffer) pullBuffer(n int) buffer.Buffer {
	var views []*buffer.View
	c := 0
	if b.skipsVnetHdr {
		c += virtioNetHdrSize
		if c >= n {
			// Nothing in the packet.
			return buffer.Buffer{}
		}
	}
	// Remove the used views from the buffer.
	for i, v := range b.views {
		c += v.Size()
		if c >= n {
			b.views[i].CapLength(v.Size() - (c - n))
			views = append(views, b.views[:i+1]...)
			break
		}
	}
	for i := range views {
		b.views[i] = nil
	}
	if b.skipsVnetHdr {
		// Exclude the size of the vnet header.
		n -= virtioNetHdrSize
	}
	pulled := buffer.Buffer{}
	for _, v := range views {
		pulled.Append(v)
	}
	pulled.Truncate(int64(n))
	return pulled
}

func (b *iovecBuffer) release() {
	for _, v := range b.views {
		if v != nil {
			v.Release()
			v = nil
		}
	}
}

// readVDispatcher uses readv() system call to read inbound packets and
// dispatches them.
type readVDispatcher struct {
	stopfd.StopFD
	// fd is the file descriptor used to send and receive packets.
	fd int

	// e is the endpoint this dispatcher is attached to.
	e *endpoint

	// buf is the iovec buffer that contains the packet contents.
	buf *iovecBuffer

	// mgr is the processor goroutine manager.
	mgr *processorManager
}

func newReadVDispatcher(fd int, e *endpoint, opts *Options) (linkDispatcher, error) {
	stopFD, err := stopfd.New()
	if err != nil {
		return nil, err
	}
	d := &readVDispatcher{
		StopFD: stopFD,
		fd:     fd,
		e:      e,
	}
	skipsVnetHdr := d.e.gsoKind == stack.HostGSOSupported
	d.buf = newIovecBuffer(BufConfig, skipsVnetHdr)
	d.mgr = newProcessorManager(opts, e)
	d.mgr.start()
	return d, nil
}

func (d *readVDispatcher) release() {
	d.buf.release()
	d.mgr.close()
}

// dispatch reads one packet from the file descriptor and dispatches it.
func (d *readVDispatcher) dispatch() (bool, tcpip.Error) {
	n, errno := rawfile.BlockingReadvUntilStopped(d.EFD, d.fd, d.buf.nextIovecs())
	if n <= 0 || errno != 0 {
		return false, tcpip.TranslateErrno(errno)
	}

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: d.buf.pullBuffer(n),
	})
	defer pkt.DecRef()

	if d.e.hdrSize > 0 {
		if !d.e.parseHeader(pkt) {
			return false, nil
		}
		pkt.NetworkProtocolNumber = header.Ethernet(pkt.LinkHeader().Slice()).Type()
	}
	d.mgr.queuePacket(pkt, d.e.hdrSize > 0)
	d.mgr.wakeReady()
	return true, nil
}

// recvMMsgDispatcher uses the recvmmsg system call to read inbound packets and
// dispatches them.
type recvMMsgDispatcher struct {
	stopfd.StopFD
	// fd is the file descriptor used to send and receive packets.
	fd int

	// e is the endpoint this dispatcher is attached to.
	e *endpoint

	// bufs is an array of iovec buffers that contain packet contents.
	bufs []*iovecBuffer

	// msgHdrs is an array of MMsgHdr objects where each MMsghdr is used to
	// reference an array of iovecs in the iovecs field defined above.  This
	// array is passed as the parameter to recvmmsg call to retrieve
	// potentially more than 1 packet per unix.
	msgHdrs []rawfile.MMsgHdr

	// pkts is reused to avoid allocations.
	pkts stack.PacketBufferList

	// gro coalesces incoming packets to increase throughput.
	gro gro.GRO

	// mgr is the processor goroutine manager.
	mgr *processorManager
}

const (
	// MaxMsgsPerRecv is the maximum number of packets we want to retrieve
	// in a single RecvMMsg call.
	MaxMsgsPerRecv = 8
)

func newRecvMMsgDispatcher(fd int, e *endpoint, opts *Options) (linkDispatcher, error) {
	stopFD, err := stopfd.New()
	if err != nil {
		return nil, err
	}
	d := &recvMMsgDispatcher{
		StopFD:  stopFD,
		fd:      fd,
		e:       e,
		bufs:    make([]*iovecBuffer, MaxMsgsPerRecv),
		msgHdrs: make([]rawfile.MMsgHdr, MaxMsgsPerRecv),
	}
	skipsVnetHdr := d.e.gsoKind == stack.HostGSOSupported
	for i := range d.bufs {
		d.bufs[i] = newIovecBuffer(BufConfig, skipsVnetHdr)
	}
	d.gro.Init(opts.GRO)
	d.mgr = newProcessorManager(opts, e)
	d.mgr.start()

	return d, nil
}

func (d *recvMMsgDispatcher) release() {
	for _, iov := range d.bufs {
		iov.release()
	}
	d.mgr.close()
}

// recvMMsgDispatch reads more than one packet at a time from the file
// descriptor and dispatches it.
func (d *recvMMsgDispatcher) dispatch() (bool, tcpip.Error) {
	// Fill message headers.
	for k := range d.msgHdrs {
		if d.msgHdrs[k].Msg.Iovlen > 0 {
			break
		}
		iovecs := d.bufs[k].nextIovecs()
		iovLen := len(iovecs)
		d.msgHdrs[k].Len = 0
		d.msgHdrs[k].Msg.Iov = &iovecs[0]
		d.msgHdrs[k].Msg.SetIovlen(iovLen)
	}

	nMsgs, errno := rawfile.BlockingRecvMMsgUntilStopped(d.EFD, d.fd, d.msgHdrs)
	if errno != 0 {
		return false, tcpip.TranslateErrno(errno)
	}
	if nMsgs == -1 {
		return false, nil
	}

	// Process each of received packets.

	d.e.mu.RLock()
	dsp := d.e.dispatcher
	d.e.mu.RUnlock()

	d.gro.Dispatcher = dsp
	defer d.pkts.Reset()

	for k := 0; k < nMsgs; k++ {
		n := int(d.msgHdrs[k].Len)
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: d.bufs[k].pullBuffer(n),
		})
		d.pkts.PushBack(pkt)

		// Mark that this iovec has been processed.
		d.msgHdrs[k].Msg.Iovlen = 0

		if d.e.hdrSize > 0 {
			hdr, ok := pkt.LinkHeader().Consume(d.e.hdrSize)
			if !ok {
				return false, nil
			}
			pkt.NetworkProtocolNumber = header.Ethernet(hdr).Type()
		}
		pkt.RXChecksumValidated = d.e.caps&stack.CapabilityRXChecksumOffload != 0
		d.mgr.queuePacket(pkt, d.e.hdrSize > 0)
	}
	d.mgr.wakeReady()

	return true, nil
}
