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

package tun

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	// drivers/net/tun.c:tun_net_init()
	defaultDevMtu = 1500

	// Queue length for outbound packet, arriving at fd side for read. Overflow
	// causes packet drops. gVisor implementation-specific.
	defaultDevOutQueueLen = 1024
)

var zeroMAC [6]byte

// Device is an opened /dev/net/tun device.
//
// +stateify savable
type Device struct {
	waiter.Queue

	mu           sync.RWMutex `state:"nosave"`
	endpoint     *tunEndpoint
	notifyHandle *channel.NotificationHandle
	flags        uint16
}

// beforeSave is invoked by stateify.
func (d *Device) beforeSave() {
	d.mu.Lock()
	defer d.mu.Unlock()
	// TODO(b/110961832): Restore the device to stack. At this moment, the stack
	// is not savable.
	if d.endpoint != nil {
		panic("/dev/net/tun does not support save/restore when a device is associated with it.")
	}
}

// Release implements fs.FileOperations.Release.
func (d *Device) Release(ctx context.Context) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Decrease refcount if there is an endpoint associated with this file.
	if d.endpoint != nil {
		d.endpoint.RemoveNotify(d.notifyHandle)
		d.endpoint.DecRef(ctx)
		d.endpoint = nil
	}
}

// NICID returns the NIC ID of the device.
//
// Must only be called after the device has been attached to an endpoint.
func (d *Device) NICID() tcpip.NICID {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.endpoint == nil {
		panic("called NICID on a device that has not been attached")
	}

	return d.endpoint.nicID
}

// SetIff services TUNSETIFF ioctl(2) request.
//
// Returns true if a new NIC was created; false if an existing one was attached.
func (d *Device) SetIff(s *stack.Stack, name string, flags uint16) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.endpoint != nil {
		return false, syserror.EINVAL
	}

	// Input validations.
	isTun := flags&linux.IFF_TUN != 0
	isTap := flags&linux.IFF_TAP != 0
	supportedFlags := uint16(linux.IFF_TUN | linux.IFF_TAP | linux.IFF_NO_PI)
	if isTap && isTun || !isTap && !isTun || flags&^supportedFlags != 0 {
		return false, syserror.EINVAL
	}

	prefix := "tun"
	if isTap {
		prefix = "tap"
	}

	linkCaps := stack.CapabilityNone
	if isTap {
		linkCaps |= stack.CapabilityResolutionRequired
	}

	endpoint, created, err := attachOrCreateNIC(s, name, prefix, linkCaps)
	if err != nil {
		return false, syserror.EINVAL
	}

	d.endpoint = endpoint
	d.notifyHandle = d.endpoint.AddNotify(d)
	d.flags = flags
	return created, nil
}

func attachOrCreateNIC(s *stack.Stack, name, prefix string, linkCaps stack.LinkEndpointCapabilities) (*tunEndpoint, bool, error) {
	for {
		// 1. Try to attach to an existing NIC.
		if name != "" {
			if linkEP := s.GetLinkEndpointByName(name); linkEP != nil {
				endpoint, ok := linkEP.(*tunEndpoint)
				if !ok {
					// Not a NIC created by tun device.
					return nil, false, syserror.EOPNOTSUPP
				}
				if !endpoint.TryIncRef() {
					// Race detected: NIC got deleted in between.
					continue
				}
				return endpoint, false, nil
			}
		}

		// 2. Creating a new NIC.
		id := tcpip.NICID(s.UniqueID())
		endpoint := &tunEndpoint{
			Endpoint: channel.New(defaultDevOutQueueLen, defaultDevMtu, ""),
			stack:    s,
			nicID:    id,
			name:     name,
			isTap:    prefix == "tap",
		}
		endpoint.InitRefs()
		endpoint.Endpoint.LinkEPCapabilities = linkCaps
		if endpoint.name == "" {
			endpoint.name = fmt.Sprintf("%s%d", prefix, id)
		}
		err := s.CreateNICWithOptions(endpoint.nicID, endpoint, stack.NICOptions{
			Name: endpoint.name,
		})
		switch err {
		case nil:
			return endpoint, true, nil
		case tcpip.ErrDuplicateNICID:
			// Race detected: A NIC has been created in between.
			continue
		default:
			return nil, false, syserror.EINVAL
		}
	}
}

// Write inject one inbound packet to the network interface.
func (d *Device) Write(data []byte) (int64, error) {
	d.mu.RLock()
	endpoint := d.endpoint
	d.mu.RUnlock()
	if endpoint == nil {
		return 0, syserror.EBADFD
	}
	if !endpoint.IsAttached() {
		return 0, syserror.EIO
	}

	dataLen := int64(len(data))

	// Packet information.
	var pktInfoHdr PacketInfoHeader
	if !d.hasFlags(linux.IFF_NO_PI) {
		if len(data) < PacketInfoHeaderSize {
			// Ignore bad packet.
			return dataLen, nil
		}
		pktInfoHdr = PacketInfoHeader(data[:PacketInfoHeaderSize])
		data = data[PacketInfoHeaderSize:]
	}

	// Ethernet header (TAP only).
	var ethHdr header.Ethernet
	if d.hasFlags(linux.IFF_TAP) {
		if len(data) < header.EthernetMinimumSize {
			// Ignore bad packet.
			return dataLen, nil
		}
		ethHdr = header.Ethernet(data[:header.EthernetMinimumSize])
		data = data[header.EthernetMinimumSize:]
	}

	// Try to determine network protocol number, default zero.
	var protocol tcpip.NetworkProtocolNumber
	switch {
	case pktInfoHdr != nil:
		protocol = pktInfoHdr.Protocol()
	case ethHdr != nil:
		protocol = ethHdr.Type()
	}

	// Try to determine remote link address, default zero.
	var remote tcpip.LinkAddress
	switch {
	case ethHdr != nil:
		remote = ethHdr.SourceAddress()
	default:
		remote = tcpip.LinkAddress(zeroMAC[:])
	}

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: len(ethHdr),
		Data:               buffer.View(data).ToVectorisedView(),
	})
	copy(pkt.LinkHeader().Push(len(ethHdr)), ethHdr)
	endpoint.InjectLinkAddr(protocol, remote, pkt)
	return dataLen, nil
}

// Read reads one outgoing packet from the network interface.
func (d *Device) Read() ([]byte, error) {
	d.mu.RLock()
	endpoint := d.endpoint
	d.mu.RUnlock()
	if endpoint == nil {
		return nil, syserror.EBADFD
	}

	for {
		info, ok := endpoint.Read()
		if !ok {
			return nil, syserror.ErrWouldBlock
		}

		v, ok := d.encodePkt(&info)
		if !ok {
			// Ignore unsupported packet.
			continue
		}
		return v, nil
	}
}

// encodePkt encodes packet for fd side.
func (d *Device) encodePkt(info *channel.PacketInfo) (buffer.View, bool) {
	var vv buffer.VectorisedView

	// Packet information.
	if !d.hasFlags(linux.IFF_NO_PI) {
		hdr := make(PacketInfoHeader, PacketInfoHeaderSize)
		hdr.Encode(&PacketInfoFields{
			Protocol: info.Proto,
		})
		vv.AppendView(buffer.View(hdr))
	}

	// If the packet does not already have link layer header, and the route
	// does not exist, we can't compute it. This is possibly a raw packet, tun
	// device doesn't support this at the moment.
	if info.Pkt.LinkHeader().View().IsEmpty() && info.Route.RemoteLinkAddress == "" {
		return nil, false
	}

	// Ethernet header (TAP only).
	if d.hasFlags(linux.IFF_TAP) {
		// Add ethernet header if not provided.
		if info.Pkt.LinkHeader().View().IsEmpty() {
			d.endpoint.AddHeader(info.Route.LocalLinkAddress, info.Route.RemoteLinkAddress, info.Proto, info.Pkt)
		}
		vv.AppendView(info.Pkt.LinkHeader().View())
	}

	// Append upper headers.
	vv.AppendView(info.Pkt.NetworkHeader().View())
	vv.AppendView(info.Pkt.TransportHeader().View())
	// Append data payload.
	vv.Append(info.Pkt.Data)

	return vv.ToView(), true
}

// Name returns the name of the attached network interface. Empty string if
// unattached.
func (d *Device) Name() string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.endpoint != nil {
		return d.endpoint.name
	}
	return ""
}

// Flags returns the flags set for d. Zero value if unset.
func (d *Device) Flags() uint16 {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.flags
}

func (d *Device) hasFlags(flags uint16) bool {
	return d.flags&flags == flags
}

// Readiness implements watier.Waitable.Readiness.
func (d *Device) Readiness(mask waiter.EventMask) waiter.EventMask {
	if mask&waiter.EventIn != 0 {
		d.mu.RLock()
		endpoint := d.endpoint
		d.mu.RUnlock()
		if endpoint != nil && endpoint.NumQueued() == 0 {
			mask &= ^waiter.EventIn
		}
	}
	return mask & (waiter.EventIn | waiter.EventOut)
}

// WriteNotify implements channel.Notification.WriteNotify.
func (d *Device) WriteNotify() {
	d.Notify(waiter.EventIn)
}

// tunEndpoint is the link endpoint for the NIC created by the tun device.
//
// It is ref-counted as multiple opening files can attach to the same NIC.
// The last owner is responsible for deleting the NIC.
type tunEndpoint struct {
	tunEndpointRefs
	*channel.Endpoint

	stack *stack.Stack
	nicID tcpip.NICID
	name  string
	isTap bool
}

// DecRef decrements refcount of e, removing NIC if it reaches 0.
func (e *tunEndpoint) DecRef(ctx context.Context) {
	e.tunEndpointRefs.DecRef(func() {
		e.stack.RemoveNIC(e.nicID)
	})
}

// ARPHardwareType implements stack.LinkEndpoint.ARPHardwareType.
func (e *tunEndpoint) ARPHardwareType() header.ARPHardwareType {
	if e.isTap {
		return header.ARPHardwareEther
	}
	return header.ARPHardwareNone
}

// AddHeader implements stack.LinkEndpoint.AddHeader.
func (e *tunEndpoint) AddHeader(local, remote tcpip.LinkAddress, protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	if !e.isTap {
		return
	}
	eth := header.Ethernet(pkt.LinkHeader().Push(header.EthernetMinimumSize))
	hdr := &header.EthernetFields{
		SrcAddr: local,
		DstAddr: remote,
		Type:    protocol,
	}
	if hdr.SrcAddr == "" {
		hdr.SrcAddr = e.LinkAddress()
	}

	eth.Encode(hdr)
}

// MaxHeaderLength returns the maximum size of the link layer header.
func (e *tunEndpoint) MaxHeaderLength() uint16 {
	if e.isTap {
		return header.EthernetMinimumSize
	}
	return 0
}
