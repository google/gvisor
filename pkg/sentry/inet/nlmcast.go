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

// InterfaceEventSubscriber allows clients to subscribe to events published by an inet.Stack.
//
// It is a rough parallel to the objects in Linux that subscribe to netdev
// events by calling register_netdevice_notifier().
type InterfaceEventSubscriber interface {
	// OnInterfaceChangeEvent is called by InterfaceEventPublishers when an interface change event takes place.
	OnInterfaceChangeEvent(ctx context.Context, idx int32, i Interface)

	// OnInterfaceDeleteEvent is called by InterfaceEventPublishers when an interface delete event takes place.
	OnInterfaceDeleteEvent(ctx context.Context, idx int32, i Interface)
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

// NewNetlinkMcastTable creates a new McastTable.
func NewNetlinkMcastTable() *McastTable {
	return &McastTable{
		socks: make(map[int]map[NetlinkSocket]struct{}),
	}
}
