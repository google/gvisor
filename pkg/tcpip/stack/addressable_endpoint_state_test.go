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
	var ep fakeNetworkEndpoint
	if err := ep.Enable(); err != nil {
		t.Fatalf("ep.Enable(): %s", err)
	}

	var s stack.AddressableEndpointState
	s.Init(&ep, stack.AddressableEndpointStateOptions{HiddenWhileDisabled: false})

	addr := tcpip.AddressWithPrefix{
		Address:   tcpip.AddrFromSlice([]byte("\x01\x00\x00\x00")),
		PrefixLen: 32,
	}

	{
		properties := stack.AddressProperties{PEB: stack.NeverPrimaryEndpoint}
		ep, err := s.AddAndAcquirePermanentAddress(addr, properties)
		if err != nil {
			t.Fatalf("s.AddAndAcquirePermanentAddress(%s, %+v): %s", addr, properties, err)
		}
		// We don't need the address endpoint.
		ep.DecRef()
	}
	{
		ep := s.AcquireAssignedAddress(addr.Address, false /* allowTemp */, stack.NeverPrimaryEndpoint, true /* readOnly */)
		if ep == nil {
			t.Fatalf("got s.AcquireAssignedAddress(%s, false, NeverPrimaryEndpoint) = nil, want = non-nil", addr.Address)
		}
	}

	s.Cleanup()
	if ep := s.AcquireAssignedAddress(addr.Address, false /* allowTemp */, stack.NeverPrimaryEndpoint, true /* readOnly */); ep != nil {
		t.Fatalf("got s.AcquireAssignedAddress(%s, false, NeverPrimaryEndpoint) = %s, want = nil", addr.Address, ep.AddressWithPrefix())
	}
}

func TestAddressDispatcherExpiredToAssigned(t *testing.T) {
	var networkEp fakeNetworkEndpoint
	if err := networkEp.Enable(); err != nil {
		t.Fatalf("ep.Enable(): %s", err)
	}

	var s stack.AddressableEndpointState
	s.Init(&networkEp, stack.AddressableEndpointStateOptions{HiddenWhileDisabled: false})

	addr := tcpip.AddressWithPrefix{
		Address:   tcpip.AddrFromSlice([]byte("\x01\x00\x00\x00")),
		PrefixLen: 32,
	}

	ep, err := s.AddAndAcquirePermanentAddress(addr, stack.AddressProperties{})
	if err != nil {
		t.Fatalf("s.AddAndAcquirePermanentAddress(%s, {}): %s", addr, err)
	}
	defer ep.DecRef()
	if !ep.TryIncRef() {
		t.Fatalf("failed to increase ref count of address endpoint")
	}

	if err := s.RemovePermanentEndpoint(ep, stack.AddressRemovalManualAction); err != nil {
		ep.DecRef()
		t.Fatalf("s.RemovePermanentEndpoint(ep, stack.AddressRemovalManualAction): %s", err)
	}

	addrDisp := &addressDispatcher{
		changedCh: make(chan addressChangedEvent, 1),
		removedCh: make(chan stack.AddressRemovalReason, 1),
		addr:      addr,
	}
	properties := stack.AddressProperties{Disp: addrDisp}
	readdedEp, err := s.AddAndAcquirePermanentAddress(addr, properties)
	if err != nil {
		t.Fatalf("s.AddAndAcquirePermanentAddress(%s, %+v): %s", addr, properties, err)
	}
	defer readdedEp.DecRef()
	if err := addrDisp.expectChanged(stack.AddressLifetimes{}, stack.AddressAssigned); err != nil {
		t.Fatalf("expect to observe address added: %s", err)
	}
}

// TestAddressableEndpointStateDisabled tests address acquisition while the
// network endpoint is disabled.
func TestAddressableEndpointStateDisabled(t *testing.T) {
	addr := tcpip.AddressWithPrefix{
		Address:   tcpip.AddrFromSlice([]byte("\x01\x00\x00\x00")),
		PrefixLen: 32,
	}

	for _, tc := range []struct {
		name                string
		hiddenWhileDisabled bool
	}{
		{
			name: "acquiresPermanentAddrWhenVisible",
		},
		{
			name:                "hidesPermanentAddrWhenHidden",
			hiddenWhileDisabled: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var networkEp fakeNetworkEndpoint
			var s stack.AddressableEndpointState
			s.Init(&networkEp, stack.AddressableEndpointStateOptions{
				HiddenWhileDisabled: tc.hiddenWhileDisabled,
			})
			defer s.Cleanup()

			// Temporary addresses should never be created on a disabled endpoint.
			if got := s.AcquireAssignedAddress(addr.Address, true /* allowTemp */, stack.NeverPrimaryEndpoint, true /* readOnly */); got != nil {
				t.Errorf("s.AcquireAssignedAddress(%s, true, ...) = %v while disabled, want = nil", addr.Address, got)
			}

			ep, err := s.AddAndAcquirePermanentAddress(addr, stack.AddressProperties{PEB: stack.CanBePrimaryEndpoint})
			if err != nil {
				t.Fatalf("s.AddAndAcquirePermanentAddress(%s, ...): %s", addr, err)
			}
			ep.DecRef()

			wantAddress := !tc.hiddenWhileDisabled
			if got := s.AcquireAssignedAddress(addr.Address, tc.hiddenWhileDisabled /* allowTemp */, stack.NeverPrimaryEndpoint, true /* readOnly */); (got != nil) != wantAddress {
				t.Errorf("s.AcquireAssignedAddress(%s, %t, ...) = %v while disabled, wantAddress=%t", addr.Address, tc.hiddenWhileDisabled, got, wantAddress)
			}

			got := s.AcquireOutgoingPrimaryAddress(addr.Address, tcpip.Address{} /* srcHint */, true /* allowExpired */)
			if got != nil {
				got.DecRef()
			}
			if (got != nil) != wantAddress {
				t.Errorf("s.AcquireOutgoingPrimaryAddress(%s, '', true) = %v while disabled, wantAddress=%t", addr.Address, got, wantAddress)
			}
		})
	}
}
