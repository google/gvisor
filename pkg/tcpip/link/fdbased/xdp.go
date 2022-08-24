// Copyright 2022 The gVisor Authors.
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

//go:build (linux && amd64) || (linux && arm64)
// +build linux,amd64 linux,arm64

package fdbased

import (
	"fmt"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/bufferv2"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/rawfile"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/xdp"
)

// xdpDispatcher utilizes AF_XDP to dispatch incoming packets.
//
// xdpDispatcher is experimental and should not be used in production.
type xdpDispatcher struct {
	// stopFd enables the dispatched to be stopped via stop().
	stopFd

	// ep is the endpoint this dispatcher is attached to.
	ep *endpoint

	// fd is the AF_XDP socket FD.
	fd int

	// The following control the AF_XDP socket.
	umem      *xdp.UMEM
	fillQueue *xdp.FillQueue
	rxQueue   *xdp.RXQueue
}

func newAFXDPDispatcher(fd int, ep *endpoint, index int) (linkDispatcher, error) {
	stopFd, err := newStopFd()
	if err != nil {
		return nil, err
	}
	dispatcher := xdpDispatcher{
		stopFd: stopFd,
		fd:     fd,
		ep:     ep,
	}

	// Use a 2MB UMEM to match the PACKET_MMAP dispatcher.
	opts := xdp.DefaultReadOnlyOpts()
	opts.NFrames = (1 << 21) / opts.FrameSize
	dispatcher.umem, dispatcher.fillQueue, dispatcher.rxQueue, err = xdp.ReadOnlyFromSocket(fd, uint32(index), 0 /* queueID */, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create AF_XDP dispatcher: %v", err)
	}
	dispatcher.fillQueue.FillAll()
	return &dispatcher, nil
}

func (xd *xdpDispatcher) dispatch() (bool, tcpip.Error) {
	for {
		stopped, errno := rawfile.BlockingPollUntilStopped(xd.efd, xd.fd, unix.POLLIN|unix.POLLERR)
		if errno != 0 {
			if errno == unix.EINTR {
				continue
			}
			return !stopped, rawfile.TranslateErrno(errno)
		}
		if stopped {
			return true, nil
		}

		// Avoid the cost of the poll syscall if possible by peeking
		// until there are no packets left.
		for {
			xd.fillQueue.FillAll()

			// We can receive multiple packets at once.
			nReceived, rxIndex := xd.rxQueue.Peek()

			if nReceived == 0 {
				break
			}

			for i := uint32(0); i < nReceived; i++ {
				// Copy packet bytes into a view and free up the
				// buffer.
				descriptor := xd.rxQueue.Get(rxIndex + i)
				data := xd.umem.Get(descriptor)
				view := bufferv2.NewView(int(descriptor.Len))
				view.Write(data)
				xd.umem.FreeFrame(descriptor.Addr)

				// Determine the network protocol.
				var netProto tcpip.NetworkProtocolNumber
				if xd.ep.hdrSize > 0 {
					netProto = header.Ethernet(data).Type()
				} else {
					// We don't get any indication of what the packet is, so try to guess
					// if it's an IPv4 or IPv6 packet.
					switch header.IPVersion(data) {
					case header.IPv4Version:
						netProto = header.IPv4ProtocolNumber
					case header.IPv6Version:
						netProto = header.IPv6ProtocolNumber
					default:
						return true, nil
					}
				}

				// Wrap the packet in a PacketBuffer and send it up the stack.
				pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
					Payload: bufferv2.MakeWithView(view),
				})
				if xd.ep.hdrSize > 0 {
					if _, ok := pkt.LinkHeader().Consume(xd.ep.hdrSize); !ok {
						panic(fmt.Sprintf("LinkHeader().Consume(%d) must succeed", xd.ep.hdrSize))
					}
				}
				xd.ep.dispatcher.DeliverNetworkPacket(netProto, pkt)
				pkt.DecRef()
			}
			// Tell the kernel that we're done with these packets.
			xd.rxQueue.Release(nReceived)
		}

		return true, nil
	}
}

func (*xdpDispatcher) release() {
	// Noop: let the kernel clean up.
}
