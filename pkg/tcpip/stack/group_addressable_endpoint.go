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

package stack

import (
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
)

// GroupAddressableEndpoint is an endpoint that supports group addressing.
//
// An endpoint is considered to support group addressing when one or more
// endpoints may associate itself with an identifier (group address) that is
// used to filter incoming packets before processing them. That is, if an
// incoming group-directed packet does not hold a group address an endpoint is
// associated with, the endpoint should not process it.
//
// This endpoint is expected to reference count joins so that a group is only
// left once each join is matched with a leave.
type GroupAddressableEndpoint interface {
	// JoinGroup joins the spcified group.
	//
	// If the endoint is already a member of the group, the group's join count
	// will be incremented.
	//
	// Returns true if the group was newly joined.
	JoinGroup(group tcpip.Address) (bool, *tcpip.Error)

	// LeaveGroup decrements the join count and leaves the specified group once
	// the join count reaches 0.
	//
	// Returns true if the group was left (join count hit 0).
	LeaveGroup(group tcpip.Address) (bool, *tcpip.Error)

	// IsInGroup returns true if the endpoint is a member of the specified group.
	IsInGroup(group tcpip.Address) bool

	// LeaveAllGroups forcefully leaves all groups.
	LeaveAllGroups() *tcpip.Error
}

// NewGroupAddressableEndpointState returns a GroupAddressableEndpointState.
func NewGroupAddressableEndpointState(addressableEndpoint AddressableEndpoint) *GroupAddressableEndpointState {
	g := &GroupAddressableEndpointState{
		addressableEndpoint: addressableEndpoint,
	}
	g.mu.joins = make(map[tcpip.Address]uint32)
	return g
}

var _ GroupAddressableEndpoint = (*GroupAddressableEndpointState)(nil)

// GroupAddressableEndpointState is an implementation of a
// GroupAddressableEndpoint that depends on an AddressableEndpoint.
type GroupAddressableEndpointState struct {
	addressableEndpoint AddressableEndpoint

	mu struct {
		sync.RWMutex

		joins map[tcpip.Address]uint32
	}
}

// JoinGroup implements GroupAddressableEndpoint.
func (g *GroupAddressableEndpointState) JoinGroup(addr tcpip.Address) (bool, *tcpip.Error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	// TODO: don't add groups like a normal address.
	joins := g.mu.joins[addr]
	if joins == 0 {
		_, err := g.addressableEndpoint.AddPermanentAddress(tcpip.AddressWithPrefix{
			Address:   addr,
			PrefixLen: len(addr) * 8,
		}, NeverPrimaryEndpoint, AddressConfigStatic, false /* deprecated */)
		if err != nil {
			return false, err
		}
	}

	g.mu.joins[addr] = joins + 1
	return joins == 0, nil
}

// LeaveGroup implements GroupAddressableEndpoint.
func (g *GroupAddressableEndpointState) LeaveGroup(addr tcpip.Address) (bool, *tcpip.Error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.leaveGroupLocked(addr, false /* force */)
}

// leaveGroupLocked is like LeaveGroup.
//
// Precondition: g.mu must be write locked.
func (g *GroupAddressableEndpointState) leaveGroupLocked(addr tcpip.Address, force bool) (bool, *tcpip.Error) {
	joins, ok := g.mu.joins[addr]
	if !ok {
		return false, tcpip.ErrBadLocalAddress
	}

	g.mu.joins[addr] = joins - 1
	if force || joins == 1 {
		if err := g.addressableEndpoint.RemovePermanentAddress(addr); err != nil {
			return false, err
		}
		delete(g.mu.joins, addr)
	}

	return force || joins == 1, nil
}

// IsInGroup implements GroupAddressableEndpoint.
func (g *GroupAddressableEndpointState) IsInGroup(addr tcpip.Address) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()

	return g.mu.joins[addr] != 0
}

// LeaveAllGroups implements GroupAddressableEndpoint.
func (g *GroupAddressableEndpointState) LeaveAllGroups() *tcpip.Error {
	g.mu.Lock()
	defer g.mu.Unlock()

	var errRet *tcpip.Error
	for addr := range g.mu.joins {
		if _, err := g.leaveGroupLocked(addr, true /* force */); err != nil && errRet == nil {
			errRet = err
		}
	}
	return errRet
}
