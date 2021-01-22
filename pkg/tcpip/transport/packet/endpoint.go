// Copyright 2019 The gVisor Authors.
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

// Package packet provides the implementation of packet sockets (see
// packet(7)). Packet sockets allow applications to:
//
//   * manually write and inspect link, network, and transport headers
//   * receive all traffic of a given network protocol, or all protocols
//
// Packet sockets are similar to raw sockets, but provide even more power to
// users, letting them effectively talk directly to the network device.
//
// Packet sockets skip the input and output iptables chains.
package packet

import (
	"fmt"
	"io"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/waiter"
)

// +stateify savable
type packet struct {
	packetEntry
	// data holds the actual packet data, including any headers and
	// payload.
	data buffer.VectorisedView `state:".(buffer.VectorisedView)"`
	// timestampNS is the unix time at which the packet was received.
	timestampNS int64
	// senderAddr is the network address of the sender.
	senderAddr tcpip.FullAddress
	// packetInfo holds additional information like the protocol
	// of the packet etc.
	packetInfo tcpip.LinkPacketInfo
}

// endpoint is the packet socket implementation of tcpip.Endpoint. It is legal
// to have goroutines make concurrent calls into the endpoint.
//
// Lock order:
//   endpoint.mu
//     endpoint.rcvMu
//
// +stateify savable
type endpoint struct {
	stack.TransportEndpointInfo
	tcpip.DefaultSocketOptionsHandler

	// The following fields are initialized at creation time and are
	// immutable.
	stack       *stack.Stack `state:"manual"`
	netProto    tcpip.NetworkProtocolNumber
	waiterQueue *waiter.Queue
	cooked      bool

	// The following fields are used to manage the receive queue and are
	// protected by rcvMu.
	rcvMu         sync.Mutex `state:"nosave"`
	rcvList       packetList
	rcvBufSizeMax int `state:".(int)"`
	rcvBufSize    int
	rcvClosed     bool

	// The following fields are protected by mu.
	mu            sync.RWMutex `state:"nosave"`
	sndBufSize    int
	sndBufSizeMax int
	closed        bool
	stats         tcpip.TransportEndpointStats `state:"nosave"`
	bound         bool
	boundNIC      tcpip.NICID

	// lastErrorMu protects lastError.
	lastErrorMu sync.Mutex   `state:"nosave"`
	lastError   *tcpip.Error `state:".(string)"`

	// ops is used to get socket level options.
	ops tcpip.SocketOptions
}

// NewEndpoint returns a new packet endpoint.
func NewEndpoint(s *stack.Stack, cooked bool, netProto tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, *tcpip.Error) {
	ep := &endpoint{
		stack: s,
		TransportEndpointInfo: stack.TransportEndpointInfo{
			NetProto: netProto,
		},
		cooked:        cooked,
		netProto:      netProto,
		waiterQueue:   waiterQueue,
		rcvBufSizeMax: 32 * 1024,
		sndBufSize:    32 * 1024,
	}
	ep.ops.InitHandler(ep)

	// Override with stack defaults.
	var ss stack.SendBufferSizeOption
	if err := s.Option(&ss); err == nil {
		ep.sndBufSizeMax = ss.Default
	}

	var rs stack.ReceiveBufferSizeOption
	if err := s.Option(&rs); err == nil {
		ep.rcvBufSizeMax = rs.Default
	}

	if err := s.RegisterPacketEndpoint(0, netProto, ep); err != nil {
		return nil, err
	}
	return ep, nil
}

// Abort implements stack.TransportEndpoint.Abort.
func (ep *endpoint) Abort() {
	ep.Close()
}

// Close implements tcpip.Endpoint.Close.
func (ep *endpoint) Close() {
	ep.mu.Lock()
	defer ep.mu.Unlock()

	if ep.closed {
		return
	}

	ep.stack.UnregisterPacketEndpoint(0, ep.netProto, ep)

	ep.rcvMu.Lock()
	defer ep.rcvMu.Unlock()

	// Clear the receive list.
	ep.rcvClosed = true
	ep.rcvBufSize = 0
	for !ep.rcvList.Empty() {
		ep.rcvList.Remove(ep.rcvList.Front())
	}

	ep.closed = true
	ep.bound = false
	ep.waiterQueue.Notify(waiter.EventHUp | waiter.EventErr | waiter.EventIn | waiter.EventOut)
}

// ModerateRecvBuf implements tcpip.Endpoint.ModerateRecvBuf.
func (ep *endpoint) ModerateRecvBuf(copied int) {}

// Read implements tcpip.Endpoint.Read.
func (ep *endpoint) Read(dst io.Writer, opts tcpip.ReadOptions) (tcpip.ReadResult, *tcpip.Error) {
	ep.rcvMu.Lock()

	// If there's no data to read, return that read would block or that the
	// endpoint is closed.
	if ep.rcvList.Empty() {
		err := tcpip.ErrWouldBlock
		if ep.rcvClosed {
			ep.stats.ReadErrors.ReadClosed.Increment()
			err = tcpip.ErrClosedForReceive
		}
		ep.rcvMu.Unlock()
		return tcpip.ReadResult{}, err
	}

	packet := ep.rcvList.Front()
	if !opts.Peek {
		ep.rcvList.Remove(packet)
		ep.rcvBufSize -= packet.data.Size()
	}

	ep.rcvMu.Unlock()

	res := tcpip.ReadResult{
		Total: packet.data.Size(),
		ControlMessages: tcpip.ControlMessages{
			HasTimestamp: true,
			Timestamp:    packet.timestampNS,
		},
	}
	if opts.NeedRemoteAddr {
		res.RemoteAddr = packet.senderAddr
	}
	if opts.NeedLinkPacketInfo {
		res.LinkPacketInfo = packet.packetInfo
	}

	n, err := packet.data.ReadTo(dst, opts.Peek)
	if n == 0 && err != nil {
		return res, tcpip.ErrBadBuffer
	}
	res.Count = n
	return res, nil
}

func (*endpoint) Write(tcpip.Payloader, tcpip.WriteOptions) (int64, *tcpip.Error) {
	// TODO(gvisor.dev/issue/173): Implement.
	return 0, tcpip.ErrInvalidOptionValue
}

// Disconnect implements tcpip.Endpoint.Disconnect. Packet sockets cannot be
// disconnected, and this function always returns tpcip.ErrNotSupported.
func (*endpoint) Disconnect() *tcpip.Error {
	return tcpip.ErrNotSupported
}

// Connect implements tcpip.Endpoint.Connect. Packet sockets cannot be
// connected, and this function always returnes tcpip.ErrNotSupported.
func (*endpoint) Connect(addr tcpip.FullAddress) *tcpip.Error {
	return tcpip.ErrNotSupported
}

// Shutdown implements tcpip.Endpoint.Shutdown. Packet sockets cannot be used
// with Shutdown, and this function always returns tcpip.ErrNotSupported.
func (*endpoint) Shutdown(flags tcpip.ShutdownFlags) *tcpip.Error {
	return tcpip.ErrNotSupported
}

// Listen implements tcpip.Endpoint.Listen. Packet sockets cannot be used with
// Listen, and this function always returns tcpip.ErrNotSupported.
func (*endpoint) Listen(backlog int) *tcpip.Error {
	return tcpip.ErrNotSupported
}

// Accept implements tcpip.Endpoint.Accept. Packet sockets cannot be used with
// Accept, and this function always returns tcpip.ErrNotSupported.
func (*endpoint) Accept(*tcpip.FullAddress) (tcpip.Endpoint, *waiter.Queue, *tcpip.Error) {
	return nil, nil, tcpip.ErrNotSupported
}

// Bind implements tcpip.Endpoint.Bind.
func (ep *endpoint) Bind(addr tcpip.FullAddress) *tcpip.Error {
	// TODO(gvisor.dev/issue/173): Add Bind support.

	// "By default, all packets of the specified protocol type are passed
	// to a packet socket.  To get packets only from a specific interface
	// use bind(2) specifying an address in a struct sockaddr_ll to bind
	// the packet socket  to  an interface.  Fields used for binding are
	// sll_family (should be AF_PACKET), sll_protocol, and sll_ifindex."
	// - packet(7).

	ep.mu.Lock()
	defer ep.mu.Unlock()

	if ep.bound && ep.boundNIC == addr.NIC {
		// If the NIC being bound is the same then just return success.
		return nil
	}

	// Unregister endpoint with all the nics.
	ep.stack.UnregisterPacketEndpoint(0, ep.netProto, ep)
	ep.bound = false

	// Bind endpoint to receive packets from specific interface.
	if err := ep.stack.RegisterPacketEndpoint(addr.NIC, ep.netProto, ep); err != nil {
		return err
	}

	ep.bound = true
	ep.boundNIC = addr.NIC

	return nil
}

// GetLocalAddress implements tcpip.Endpoint.GetLocalAddress.
func (*endpoint) GetLocalAddress() (tcpip.FullAddress, *tcpip.Error) {
	return tcpip.FullAddress{}, tcpip.ErrNotSupported
}

// GetRemoteAddress implements tcpip.Endpoint.GetRemoteAddress.
func (*endpoint) GetRemoteAddress() (tcpip.FullAddress, *tcpip.Error) {
	// Even a connected socket doesn't return a remote address.
	return tcpip.FullAddress{}, tcpip.ErrNotConnected
}

// Readiness implements tcpip.Endpoint.Readiness.
func (ep *endpoint) Readiness(mask waiter.EventMask) waiter.EventMask {
	// The endpoint is always writable.
	result := waiter.EventOut & mask

	// Determine whether the endpoint is readable.
	if (mask & waiter.EventIn) != 0 {
		ep.rcvMu.Lock()
		if !ep.rcvList.Empty() || ep.rcvClosed {
			result |= waiter.EventIn
		}
		ep.rcvMu.Unlock()
	}

	return result
}

// SetSockOpt implements tcpip.Endpoint.SetSockOpt. Packet sockets cannot be
// used with SetSockOpt, and this function always returns
// tcpip.ErrNotSupported.
func (ep *endpoint) SetSockOpt(opt tcpip.SettableSocketOption) *tcpip.Error {
	switch opt.(type) {
	case *tcpip.SocketDetachFilterOption:
		return nil

	default:
		return tcpip.ErrUnknownProtocolOption
	}
}

// SetSockOptInt implements tcpip.Endpoint.SetSockOptInt.
func (ep *endpoint) SetSockOptInt(opt tcpip.SockOptInt, v int) *tcpip.Error {
	switch opt {
	case tcpip.SendBufferSizeOption:
		// Make sure the send buffer size is within the min and max
		// allowed.
		var ss stack.SendBufferSizeOption
		if err := ep.stack.Option(&ss); err != nil {
			panic(fmt.Sprintf("s.Option(%#v) = %s", ss, err))
		}
		if v > ss.Max {
			v = ss.Max
		}
		if v < ss.Min {
			v = ss.Min
		}
		ep.mu.Lock()
		ep.sndBufSizeMax = v
		ep.mu.Unlock()
		return nil

	case tcpip.ReceiveBufferSizeOption:
		// Make sure the receive buffer size is within the min and max
		// allowed.
		var rs stack.ReceiveBufferSizeOption
		if err := ep.stack.Option(&rs); err != nil {
			panic(fmt.Sprintf("s.Option(%#v) = %s", rs, err))
		}
		if v > rs.Max {
			v = rs.Max
		}
		if v < rs.Min {
			v = rs.Min
		}
		ep.rcvMu.Lock()
		ep.rcvBufSizeMax = v
		ep.rcvMu.Unlock()
		return nil

	default:
		return tcpip.ErrUnknownProtocolOption
	}
}

func (ep *endpoint) LastError() *tcpip.Error {
	ep.lastErrorMu.Lock()
	defer ep.lastErrorMu.Unlock()

	err := ep.lastError
	ep.lastError = nil
	return err
}

// UpdateLastError implements tcpip.SocketOptionsHandler.UpdateLastError.
func (ep *endpoint) UpdateLastError(err *tcpip.Error) {
	ep.lastErrorMu.Lock()
	ep.lastError = err
	ep.lastErrorMu.Unlock()
}

// GetSockOpt implements tcpip.Endpoint.GetSockOpt.
func (ep *endpoint) GetSockOpt(opt tcpip.GettableSocketOption) *tcpip.Error {
	return tcpip.ErrNotSupported
}

// GetSockOptInt implements tcpip.Endpoint.GetSockOptInt.
func (ep *endpoint) GetSockOptInt(opt tcpip.SockOptInt) (int, *tcpip.Error) {
	switch opt {
	case tcpip.ReceiveQueueSizeOption:
		v := 0
		ep.rcvMu.Lock()
		if !ep.rcvList.Empty() {
			p := ep.rcvList.Front()
			v = p.data.Size()
		}
		ep.rcvMu.Unlock()
		return v, nil

	case tcpip.SendBufferSizeOption:
		ep.mu.Lock()
		v := ep.sndBufSizeMax
		ep.mu.Unlock()
		return v, nil

	case tcpip.ReceiveBufferSizeOption:
		ep.rcvMu.Lock()
		v := ep.rcvBufSizeMax
		ep.rcvMu.Unlock()
		return v, nil

	default:
		return -1, tcpip.ErrUnknownProtocolOption
	}
}

// HandlePacket implements stack.PacketEndpoint.HandlePacket.
func (ep *endpoint) HandlePacket(nicID tcpip.NICID, localAddr tcpip.LinkAddress, netProto tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	ep.rcvMu.Lock()

	// Drop the packet if our buffer is currently full.
	if ep.rcvClosed {
		ep.rcvMu.Unlock()
		ep.stack.Stats().DroppedPackets.Increment()
		ep.stats.ReceiveErrors.ClosedReceiver.Increment()
		return
	}

	if ep.rcvBufSize >= ep.rcvBufSizeMax {
		ep.rcvMu.Unlock()
		ep.stack.Stats().DroppedPackets.Increment()
		ep.stats.ReceiveErrors.ReceiveBufferOverflow.Increment()
		return
	}

	wasEmpty := ep.rcvBufSize == 0

	// Push new packet into receive list and increment the buffer size.
	var packet packet
	// TODO(gvisor.dev/issue/173): Return network protocol.
	if !pkt.LinkHeader().View().IsEmpty() {
		// Get info directly from the ethernet header.
		hdr := header.Ethernet(pkt.LinkHeader().View())
		packet.senderAddr = tcpip.FullAddress{
			NIC:  nicID,
			Addr: tcpip.Address(hdr.SourceAddress()),
		}
		packet.packetInfo.Protocol = netProto
		packet.packetInfo.PktType = pkt.PktType
	} else {
		// Guess the would-be ethernet header.
		packet.senderAddr = tcpip.FullAddress{
			NIC:  nicID,
			Addr: tcpip.Address(localAddr),
		}
		packet.packetInfo.Protocol = netProto
		packet.packetInfo.PktType = pkt.PktType
	}

	if ep.cooked {
		// Cooked packets can simply be queued.
		switch pkt.PktType {
		case tcpip.PacketHost:
			packet.data = pkt.Data
		case tcpip.PacketOutgoing:
			// Strip Link Header.
			var combinedVV buffer.VectorisedView
			if v := pkt.NetworkHeader().View(); !v.IsEmpty() {
				combinedVV.AppendView(v)
			}
			if v := pkt.TransportHeader().View(); !v.IsEmpty() {
				combinedVV.AppendView(v)
			}
			combinedVV.Append(pkt.Data)
			packet.data = combinedVV
		default:
			panic(fmt.Sprintf("unexpected PktType in pkt: %+v", pkt))
		}

	} else {
		// Raw packets need their ethernet headers prepended before
		// queueing.
		var linkHeader buffer.View
		if pkt.PktType != tcpip.PacketOutgoing {
			if pkt.LinkHeader().View().IsEmpty() {
				// We weren't provided with an actual ethernet header,
				// so fake one.
				ethFields := header.EthernetFields{
					SrcAddr: tcpip.LinkAddress([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}),
					DstAddr: localAddr,
					Type:    netProto,
				}
				fakeHeader := make(header.Ethernet, header.EthernetMinimumSize)
				fakeHeader.Encode(&ethFields)
				linkHeader = buffer.View(fakeHeader)
			} else {
				linkHeader = append(buffer.View(nil), pkt.LinkHeader().View()...)
			}
			combinedVV := linkHeader.ToVectorisedView()
			combinedVV.Append(pkt.Data)
			packet.data = combinedVV
		} else {
			packet.data = buffer.NewVectorisedView(pkt.Size(), pkt.Views())
		}
	}
	packet.timestampNS = ep.stack.Clock().NowNanoseconds()

	ep.rcvList.PushBack(&packet)
	ep.rcvBufSize += packet.data.Size()

	ep.rcvMu.Unlock()
	ep.stats.PacketsReceived.Increment()
	// Notify waiters that there's data to be read.
	if wasEmpty {
		ep.waiterQueue.Notify(waiter.EventIn)
	}
}

// State implements socket.Socket.State.
func (*endpoint) State() uint32 {
	return 0
}

// Info returns a copy of the endpoint info.
func (ep *endpoint) Info() tcpip.EndpointInfo {
	ep.mu.RLock()
	// Make a copy of the endpoint info.
	ret := ep.TransportEndpointInfo
	ep.mu.RUnlock()
	return &ret
}

// Stats returns a pointer to the endpoint stats.
func (ep *endpoint) Stats() tcpip.EndpointStats {
	return &ep.stats
}

// SetOwner implements tcpip.Endpoint.SetOwner.
func (ep *endpoint) SetOwner(owner tcpip.PacketOwner) {}

// SocketOptions implements tcpip.Endpoint.SocketOptions.
func (ep *endpoint) SocketOptions() *tcpip.SocketOptions {
	return &ep.ops
}
