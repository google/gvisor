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

package stack_test

import (
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func TestJoinedGroups(t *testing.T) {
	const addr1 = tcpip.Address("\x01")
	const addr2 = tcpip.Address("\x02")

	var ep fakeNetworkEndpoint
	var s stack.AddressableEndpointState
	s.Init(&ep)

	if joined, err := s.JoinGroup(addr1); err != nil {
		t.Fatalf("JoinGroup(%s): %s", addr1, err)
	} else if !joined {
		t.Errorf("got JoinGroup(%s) = false, want = true", addr1)
	}
	if joined, err := s.JoinGroup(addr2); err != nil {
		t.Fatalf("JoinGroup(%s): %s", addr2, err)
	} else if !joined {
		t.Errorf("got JoinGroup(%s) = false, want = true", addr2)
	}

	joinedGroups := s.JoinedGroups()
	sort.Slice(joinedGroups, func(i, j int) bool { return joinedGroups[i][0] < joinedGroups[j][0] })
	if diff := cmp.Diff([]tcpip.Address{addr1, addr2}, joinedGroups); diff != "" {
		t.Errorf("joined groups mismatch (-want +got):\n%s", diff)
	}
}

// TestAddressableEndpointStateCleanup tests that cleaning up an addressable
// endpoint state removes permanent addresses and leaves groups.
func TestAddressableEndpointStateCleanup(t *testing.T) {
	var ep fakeNetworkEndpoint
	if err := ep.Enable(); err != nil {
		t.Fatalf("ep.Enable(): %s", err)
	}

	var s stack.AddressableEndpointState
	s.Init(&ep)

	addr := tcpip.AddressWithPrefix{
		Address:   "\x01",
		PrefixLen: 8,
	}

	{
		ep, err := s.AddAndAcquirePermanentAddress(addr, stack.NeverPrimaryEndpoint, stack.AddressConfigStatic, false /* deprecated */)
		if err != nil {
			t.Fatalf("s.AddAndAcquirePermanentAddress(%s, %d, %d, false): %s", addr, stack.NeverPrimaryEndpoint, stack.AddressConfigStatic, err)
		}
		// We don't need the address endpoint.
		ep.DecRef()
	}
	{
		ep := s.AcquireAssignedAddress(addr.Address, false /* allowTemp */, stack.NeverPrimaryEndpoint)
		if ep == nil {
			t.Fatalf("got s.AcquireAssignedAddress(%s, false, NeverPrimaryEndpoint) = nil, want = non-nil", addr.Address)
		}
		ep.DecRef()
	}

	group := tcpip.Address("\x02")
	if added, err := s.JoinGroup(group); err != nil {
		t.Fatalf("s.JoinGroup(%s): %s", group, err)
	} else if !added {
		t.Fatalf("got s.JoinGroup(%s) = false, want = true", group)
	}
	if !s.IsInGroup(group) {
		t.Fatalf("got s.IsInGroup(%s) = false, want = true", group)
	}

	s.Cleanup()
	{
		ep := s.AcquireAssignedAddress(addr.Address, false /* allowTemp */, stack.NeverPrimaryEndpoint)
		if ep != nil {
			ep.DecRef()
			t.Fatalf("got s.AcquireAssignedAddress(%s, false, NeverPrimaryEndpoint) = %s, want = nil", addr.Address, ep.AddressWithPrefix())
		}
	}
	if s.IsInGroup(group) {
		t.Fatalf("got s.IsInGroup(%s) = true, want = false", group)
	}
}
