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
	"gvisor.dev/gvisor/pkg/refs"
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
func (d *Device) Release() {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Decrease refcount if there is an endpoint associated with this file.
	if d.endpoint != nil {
		d.endpoint.RemoveNotify(d.notifyHandle)
		d.endpoint.DecRef()
		d.endpoint = nil
	}
}

// SetIff services TUNSETIFF ioctl(2) request.
func (d *Device) SetIff(s *stack.Stack, name string, flags uint16) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.endpoint != nil {
		return syserror.EINVAL
	}

	// Input validations.
	isTun := flags&linux.IFF_TUN != 0
	isTap := flags&linux.IFF_TAP != 0
	supportedFlags := uint16(linux.IFF_TUN | linux.IFF_TAP | linux.IFF_NO_PI)
	if isTap && isTun || !isTap && !isTun || flags&^supportedFlags != 0 {
		return syserror.EINVAL
	}

	prefix := "tun"
	if isTap {
		prefix = "tap"
	}

	linkCaps := stack.CapabilityNone
	if isTap {
		linkCaps |= stack.CapabilityResolutionRequired
	}

	endpoint, err := attachOrCreateNIC(s, name, prefix, linkCaps)
	if err != nil {
		return syserror.EINVAL
	}

	d.endpoint = endpoint
	d.notifyHandle = d.endpoint.AddNotify(d)
	d.flags = flags
	return nil
}

func attachOrCreateNIC(s *stack.Stack, name, prefix string, linkCaps stack.LinkEndpointCapabilities) (*tunEndpoint, error) {
	for {
		// 1. Try to attach to an existing NIC.
		if name != "" {
			if nic, found := s.GetNICByName(name); found {
				endpoint, ok := nic.LinkEndpoint().(*tunEndpoint)
				if !ok {
					// Not a NIC created by tun device.
					return nil, syserror.EOPNOTSUPP
				}
				if !endpoint.TryIncRef() {
					// Race detected: NIC got deleted in between.
					continue
				}
				return endpoint, nil
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
		endpoint.Endpoint.LinkEPCapabilities = linkCaps
		if endpoint.name == "" {
			endpoint.name = fmt.Sprintf("%s%d", prefix, id)
		}
		err := s.CreateNICWithOptions(endpoint.nicID, endpoint, stack.NICOptions{
			Name: endpoint.name,
		})
		switch err {
		case nil:
			return endpoint, nil
		case tcpip.ErrDuplicateNICID:
			// Race detected: A NIC has been created in between.
			continue
		default:
			return nil, syserror.EINVAL
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

	pkt := &stack.PacketBuffer{
		Data: buffer.View(data).ToVectorisedView(),
	}
	if ethHdr != nil {
		pkt.LinkHeader = buffer.View(ethHdr)
	}
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
	if info.Pkt.LinkHeader == nil && info.Route.RemoteLinkAddress == "" {
		return nil, false
	}

	// Ethernet header (TAP only).
	if d.hasFlags(linux.IFF_TAP) {
		// Add ethernet header if not provided.
		if info.Pkt.LinkHeader == nil {
			hdr := &header.EthernetFields{
				SrcAddr: info.Route.LocalLinkAddress,
				DstAddr: info.Route.RemoteLinkAddress,
				Type:    info.Proto,
			}
			if hdr.SrcAddr == "" {
				hdr.SrcAddr = d.endpoint.LinkAddress()
			}

			eth := make(header.Ethernet, header.EthernetMinimumSize)
			eth.Encode(hdr)
			vv.AppendView(buffer.View(eth))
		} else {
			vv.AppendView(info.Pkt.LinkHeader)
		}
	}

	// Append upper headers.
	vv.AppendView(buffer.View(info.Pkt.Header.View()[len(info.Pkt.LinkHeader):]))
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
	*channel.Endpoint

	refs.AtomicRefCount

	stack *stack.Stack
	nicID tcpip.NICID
	name  string
	isTap bool
}

// DecRef decrements refcount of e, removes NIC if refcount goes to 0.
func (e *tunEndpoint) DecRef() {
	e.DecRefWithDestructor(func() {
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
