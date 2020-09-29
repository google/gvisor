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
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// TestAddressableEndpointStateCleanup tests that cleaning up an addressable
// endpoint state removes permanent addresses and leaves groups.
func TestAddressableEndpointStateCleanup(t *testing.T) {
	var s stack.AddressableEndpointState
	s.Init(&fakeNetworkEndpoint{})

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
			t.Fatalf("got s.AcquireAssignedAddress(%s) = nil, want = non-nil", addr.Address)
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
			t.Fatalf("got s.AcquireAssignedAddress(%s) = %s, want = nil", addr.Address, ep.AddressWithPrefix())
		}
	}
	if s.IsInGroup(group) {
		t.Fatalf("got s.IsInGroup(%s) = true, want = false", group)
	}
}
