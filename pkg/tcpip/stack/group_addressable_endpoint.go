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
	"gvisor.dev/gvisor/pkg/tcpip"
)

// GroupAddressableEndpoint is an endpoint that supports group addressing.
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
	// If force is true, the group will be immediately left, even if there are
	// outstanding joins.
	//
	// Returns true if the group was left (join count hit 0).
	LeaveGroup(group tcpip.Address, force bool) (bool, *tcpip.Error)

	// IsInGroup returns true if the endpoint is a member of the specified group.
	IsInGroup(group tcpip.Address) bool

	// LeaveAllGroups forcefully leaves all groups.
	LeaveAllGroups() *tcpip.Error
}

// NewGroupAddressableEndpoint returns a new GroupAddressableEndpoint that
// depends on an AddressableEndpoint to join groups.
//
// The returned GroupAddressableEndpoint does not obtain any locks before
// modifying any state. If locking is required callers must do so before
// invoking methods on the returned endpoint.
func NewGroupAddressableEndpoint(addressableEndpoint AddressableEndpoint) GroupAddressableEndpoint {
	return &groupAddressableEndpointState{
		joins:               make(map[tcpip.Address]uint32),
		addressableEndpoint: addressableEndpoint,
	}
}

var _ GroupAddressableEndpoint = (*groupAddressableEndpointState)(nil)

type groupAddressableEndpointState struct {
	joins               map[tcpip.Address]uint32
	addressableEndpoint AddressableEndpoint
}

// JoinGroup implements GroupAddressableEndpoint.JoinGroup.
func (s *groupAddressableEndpointState) JoinGroup(addr tcpip.Address) (bool, *tcpip.Error) {
	// TODO: don't add groups like a normal address.
	joins := s.joins[addr]
	if joins == 0 {
		_, err := s.addressableEndpoint.AddAddress(tcpip.AddressWithPrefix{
			Address:   addr,
			PrefixLen: len(addr) * 8,
		}, AddAddressOptions{
			Deprecated: false,
			ConfigType: AddressConfigStatic,
			Kind:       Permanent,
			PEB:        NeverPrimaryEndpoint,
		})
		if err != nil {
			return false, err
		}
	}

	s.joins[addr] = joins + 1
	return joins == 0, nil
}

// LeaveGroup implements GroupAddressableEndpoint.LeaveGroup.
func (s *groupAddressableEndpointState) LeaveGroup(addr tcpip.Address, force bool) (bool, *tcpip.Error) {
	joins, ok := s.joins[addr]
	if !ok {
		return false, tcpip.ErrBadLocalAddress
	}

	s.joins[addr] = joins - 1
	if force || joins == 1 {
		if err := s.addressableEndpoint.RemoveAddress(addr); err != nil {
			return false, err
		}
		delete(s.joins, addr)
	}

	return force || joins == 1, nil
}

// IsInGroup implements GroupAddressableEndpoint.IsInGroup.
func (s *groupAddressableEndpointState) IsInGroup(addr tcpip.Address) bool {
	return s.joins[addr] != 0
}

// LeaveAllGroups implements GroupAddressableEndpoint.LeaveAllGroups.
func (s *groupAddressableEndpointState) LeaveAllGroups() *tcpip.Error {
	var errRet *tcpip.Error
	for g := range s.joins {
		if _, err := s.LeaveGroup(g, true /* force */); err != nil && errRet == nil {
			errRet = err
		}
	}
	return errRet
}
