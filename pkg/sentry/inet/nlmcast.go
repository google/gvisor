// Copyright 2025 The gVisor Authors.
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

package inet

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
)

const (
	routeProtocol       = linux.NETLINK_ROUTE
	routeLinkMcastGroup = linux.RTNLGRP_LINK
)

// NetlinkOrigin identifies the netlink request that triggered a change that
// is being relayed to multicast group members. It corresponds to the
// NETLINK_CB(skb).portid and nlh->nlmsg_seq values that Linux passes to
// rtmsg_ifa() and the FIB notifiers.
type NetlinkOrigin struct {
	// PortID is the port ID of the requesting socket.
	PortID int32

	// Seq is the sequence number of the request.
	Seq uint32
}

type netlinkOriginKey struct{}

// WithNetlinkOrigin returns a context that records the netlink request
// currently being processed.
func WithNetlinkOrigin(ctx context.Context, o NetlinkOrigin) context.Context {
	return context.WithValue(ctx, netlinkOriginKey{}, o)
}

// NetlinkOriginFromContext returns the netlink request being processed by ctx,
// or the zero value (a change not triggered by a netlink request) if none.
func NetlinkOriginFromContext(ctx context.Context) NetlinkOrigin {
	if o, ok := ctx.Value(netlinkOriginKey{}).(NetlinkOrigin); ok {
		return o
	}
	return NetlinkOrigin{}
}

// InterfaceEventSubscriber allows clients to subscribe to events published by an inet.Stack.
//
// It is a rough parallel to the objects in Linux that subscribe to netdev
// events by calling register_netdevice_notifier().
type InterfaceEventSubscriber interface {
	// OnInterfaceChangeEvent is called by InterfaceEventPublishers when an interface change event takes place.
	OnInterfaceChangeEvent(ctx context.Context, idx int32, i Interface)

	// OnInterfaceDeleteEvent is called by InterfaceEventPublishers when an interface delete event takes place.
	OnInterfaceDeleteEvent(ctx context.Context, idx int32, i Interface)

	// OnAddressEvent is called by InterfaceEventPublishers when an address is
	// added to (added is true) or removed from (added is false) the interface
	// idx. The Linux parallels are rtmsg_ifa() and inet6_ifa_notify().
	OnAddressEvent(ctx context.Context, idx int32, i Interface, a InterfaceAddr, added bool)

	// OnRouteEvent is called by InterfaceEventPublishers when a route is added
	// or replaced (added is true) or removed (added is false). nlFlags are the
	// NLM_F_* flags of the notification message. The Linux parallels are
	// rtmsg_fib() and inet6_rt_notify().
	OnRouteEvent(ctx context.Context, rt Route, added bool, nlFlags uint16)
}

// InterfaceEventPublisher is the interface event publishing aspect of an inet.Stack.
//
// The Linux parallel is how it notifies subscribers via call_netdev_notifiers().
type InterfaceEventPublisher interface {
	AddInterfaceEventSubscriber(sub InterfaceEventSubscriber)
}

// NetlinkSocket corresponds to a netlink socket.
type NetlinkSocket interface {
	// Protocol returns the netlink protocol value.
	Protocol() int

	// Groups returns the bitmap of multicast groups the socket is bound to.
	Groups() uint64

	// HandleInterfaceChangeEvent is called on NetlinkSockets that are members of the RTNLGRP_LINK
	// multicast group when an interface is modified.
	HandleInterfaceChangeEvent(context.Context, int32, Interface)

	// HandleInterfaceDeleteEvent is called on NetlinkSockets that are members of the RTNLGRP_LINK
	// multicast group when an interface is deleted.
	HandleInterfaceDeleteEvent(context.Context, int32, Interface)

	// HandleAddressEvent is called on NetlinkSockets that are members of the
	// RTNLGRP_IPV4_IFADDR or RTNLGRP_IPV6_IFADDR multicast group (matching a.Family)
	// when an address is added or removed.
	HandleAddressEvent(ctx context.Context, idx int32, i Interface, a InterfaceAddr, added bool)

	// HandleRouteEvent is called on NetlinkSockets that are members of the
	// RTNLGRP_IPV4_ROUTE or RTNLGRP_IPV6_ROUTE multicast group (matching
	// rt.Family) when a route is added, replaced or removed.
	HandleRouteEvent(ctx context.Context, rt Route, added bool, nlFlags uint16)
}

// McastTable holds multicast group membership information for netlink netlinkSocket.
// It corresponds roughly to Linux's struct netlink_table.
//
// +stateify savable
type McastTable struct {
	mu    nlmcastTableMutex `state:"nosave"`
	socks map[int]map[NetlinkSocket]struct{}
}

// WithTableLocked runs fn with the table mutex held.
func (m *McastTable) WithTableLocked(fn func()) {
	m.mu.Lock()
	defer m.mu.Unlock()
	fn()
}

// AddSocket adds a netlinkSocket to the multicast-group table.
//
// Preconditions: the netlink multicast table is locked.
func (m *McastTable) AddSocket(s NetlinkSocket) {
	p := s.Protocol()
	if _, ok := m.socks[p]; !ok {
		m.socks[p] = make(map[NetlinkSocket]struct{})
	}
	if _, ok := m.socks[p][s]; ok {
		return
	}
	m.socks[p][s] = struct{}{}
}

// RemoveSocket removes a netlinkSocket from the multicast-group table.
//
// Preconditions: the netlink multicast table is locked.
func (m *McastTable) RemoveSocket(s NetlinkSocket) {
	p := s.Protocol()
	if _, ok := m.socks[p]; !ok {
		return
	}
	if _, ok := m.socks[p][s]; !ok {
		return
	}
	delete(m.socks[p], s)
}

// ForEachMcastSock calls fn on all Netlink sockets that are members of the given multicast group.
func (m *McastTable) ForEachMcastSock(protocol int, mcastGroup int, fn func(s NetlinkSocket)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.socks[protocol]; !ok {
		return
	}
	for s := range m.socks[protocol] {
		// If the socket is not bound to the multicast group, skip it.
		if s.Groups()&(1<<(mcastGroup-1)) == 0 {
			continue
		}
		fn(s)
	}
}

// OnInterfaceChangeEvent implements InterfaceEventSubscriber.OnInterfaceChangeEvent.
func (m *McastTable) OnInterfaceChangeEvent(ctx context.Context, idx int32, i Interface) {
	// Relay the event to RTNLGRP_LINK subscribers.
	m.ForEachMcastSock(routeProtocol, routeLinkMcastGroup, func(s NetlinkSocket) {
		s.HandleInterfaceChangeEvent(ctx, idx, i)
	})
}

// OnInterfaceDeleteEvent implements InterfaceEventSubscriber.OnInterfaceDeleteEvent.
func (m *McastTable) OnInterfaceDeleteEvent(ctx context.Context, idx int32, i Interface) {
	// Relay the event to RTNLGRP_LINK subscribers.
	m.ForEachMcastSock(routeProtocol, routeLinkMcastGroup, func(s NetlinkSocket) {
		s.HandleInterfaceDeleteEvent(ctx, idx, i)
	})
}

// OnAddressEvent implements InterfaceEventSubscriber.OnAddressEvent.
func (m *McastTable) OnAddressEvent(ctx context.Context, idx int32, i Interface, a InterfaceAddr, added bool) {
	var group int
	switch a.Family {
	case linux.AF_INET:
		group = linux.RTNLGRP_IPV4_IFADDR
	case linux.AF_INET6:
		group = linux.RTNLGRP_IPV6_IFADDR
	default:
		return
	}
	m.ForEachMcastSock(routeProtocol, group, func(s NetlinkSocket) {
		s.HandleAddressEvent(ctx, idx, i, a, added)
	})
}

// OnRouteEvent implements InterfaceEventSubscriber.OnRouteEvent.
func (m *McastTable) OnRouteEvent(ctx context.Context, rt Route, added bool, nlFlags uint16) {
	var group int
	switch rt.Family {
	case linux.AF_INET:
		group = linux.RTNLGRP_IPV4_ROUTE
	case linux.AF_INET6:
		group = linux.RTNLGRP_IPV6_ROUTE
	default:
		return
	}
	m.ForEachMcastSock(routeProtocol, group, func(s NetlinkSocket) {
		s.HandleRouteEvent(ctx, rt, added, nlFlags)
	})
}

// NewNetlinkMcastTable creates a new McastTable.
func NewNetlinkMcastTable() *McastTable {
	return &McastTable{
		socks: make(map[int]map[NetlinkSocket]struct{}),
	}
}
