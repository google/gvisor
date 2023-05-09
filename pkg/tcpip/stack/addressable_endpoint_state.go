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
	"fmt"

	"gvisor.dev/gvisor/pkg/tcpip"
)

func (lifetimes *AddressLifetimes) sanitize() {
	if lifetimes.Deprecated {
		lifetimes.PreferredUntil = tcpip.MonotonicTime{}
	}
}

var _ AddressableEndpoint = (*AddressableEndpointState)(nil)

// AddressableEndpointState is an implementation of an AddressableEndpoint.
type AddressableEndpointState struct {
	networkEndpoint NetworkEndpoint
	options         AddressableEndpointStateOptions

	// Lock ordering (from outer to inner lock ordering):
	//
	// AddressableEndpointState.mu
	//   addressState.mu
	mu addressableEndpointStateRWMutex
	// +checklocks:mu
	endpoints map[tcpip.Address]*addressState
	// +checklocks:mu
	primary []*addressState
}

// AddressableEndpointStateOptions contains options used to configure an
// AddressableEndpointState.
type AddressableEndpointStateOptions struct {
	// HiddenWhileDisabled determines whether addresses should be returned to
	// callers while the NetworkEndpoint this AddressableEndpointState belongs
	// to is disabled.
	HiddenWhileDisabled bool
}

// Init initializes the AddressableEndpointState with networkEndpoint.
//
// Must be called before calling any other function on m.
func (a *AddressableEndpointState) Init(networkEndpoint NetworkEndpoint, options AddressableEndpointStateOptions) {
	a.networkEndpoint = networkEndpoint
	a.options = options

	a.mu.Lock()
	defer a.mu.Unlock()
	a.endpoints = make(map[tcpip.Address]*addressState)
}

// OnNetworkEndpointEnabledChanged must be called every time the
// NetworkEndpoint this AddressableEndpointState belongs to is enabled or
// disabled so that any AddressDispatchers can be notified of the NIC enabled
// change.
func (a *AddressableEndpointState) OnNetworkEndpointEnabledChanged() {
	a.mu.RLock()
	defer a.mu.RUnlock()

	for _, ep := range a.endpoints {
		ep.mu.Lock()
		ep.notifyChangedLocked()
		ep.mu.Unlock()
	}
}

// GetAddress returns the AddressEndpoint for the passed address.
//
// GetAddress does not increment the address's reference count or check if the
// address is considered bound to the endpoint.
//
// Returns nil if the passed address is not associated with the endpoint.
func (a *AddressableEndpointState) GetAddress(addr tcpip.Address) AddressEndpoint {
	a.mu.RLock()
	defer a.mu.RUnlock()

	ep, ok := a.endpoints[addr]
	if !ok {
		return nil
	}
	return ep
}

// ForEachEndpoint calls f for each address.
//
// Once f returns false, f will no longer be called.
func (a *AddressableEndpointState) ForEachEndpoint(f func(AddressEndpoint) bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	for _, ep := range a.endpoints {
		if !f(ep) {
			return
		}
	}
}

// ForEachPrimaryEndpoint calls f for each primary address.
//
// Once f returns false, f will no longer be called.
func (a *AddressableEndpointState) ForEachPrimaryEndpoint(f func(AddressEndpoint) bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	for _, ep := range a.primary {
		if !f(ep) {
			return
		}
	}
}

func (a *AddressableEndpointState) releaseAddressState(addrState *addressState) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.releaseAddressStateLocked(addrState)
}

// releaseAddressStateLocked removes addrState from a's address state
// (primary and endpoints list).
//
// +checklocks:a.mu
func (a *AddressableEndpointState) releaseAddressStateLocked(addrState *addressState) {
	oldPrimary := a.primary
	for i, s := range a.primary {
		if s == addrState {
			a.primary = append(a.primary[:i], a.primary[i+1:]...)
			oldPrimary[len(oldPrimary)-1] = nil
			break
		}
	}
	delete(a.endpoints, addrState.addr.Address)
}

// AddAndAcquirePermanentAddress implements AddressableEndpoint.
func (a *AddressableEndpointState) AddAndAcquirePermanentAddress(addr tcpip.AddressWithPrefix, properties AddressProperties) (AddressEndpoint, tcpip.Error) {
	return a.AddAndAcquireAddress(addr, properties, Permanent)
}

// AddAndAcquireTemporaryAddress adds a temporary address.
//
// Returns *tcpip.ErrDuplicateAddress if the address exists.
//
// The temporary address's endpoint is acquired and returned.
func (a *AddressableEndpointState) AddAndAcquireTemporaryAddress(addr tcpip.AddressWithPrefix, peb PrimaryEndpointBehavior) (AddressEndpoint, tcpip.Error) {
	return a.AddAndAcquireAddress(addr, AddressProperties{PEB: peb}, Temporary)
}

// AddAndAcquireAddress adds an address with the specified kind.
//
// Returns *tcpip.ErrDuplicateAddress if the address exists.
func (a *AddressableEndpointState) AddAndAcquireAddress(addr tcpip.AddressWithPrefix, properties AddressProperties, kind AddressKind) (AddressEndpoint, tcpip.Error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	ep, err := a.addAndAcquireAddressLocked(addr, properties, kind)
	// From https://golang.org/doc/faq#nil_error:
	//
	// Under the covers, interfaces are implemented as two elements, a type T and
	// a value V.
	//
	// An interface value is nil only if the V and T are both unset, (T=nil, V is
	// not set), In particular, a nil interface will always hold a nil type. If we
	// store a nil pointer of type *int inside an interface value, the inner type
	// will be *int regardless of the value of the pointer: (T=*int, V=nil). Such
	// an interface value will therefore be non-nil even when the pointer value V
	// inside is nil.
	//
	// Since addAndAcquireAddressLocked returns a nil value with a non-nil type,
	// we need to explicitly return nil below if ep is (a typed) nil.
	if ep == nil {
		return nil, err
	}
	return ep, err
}

// addAndAcquireAddressLocked adds, acquires and returns a permanent or
// temporary address.
//
// If the addressable endpoint already has the address in a non-permanent state,
// and addAndAcquireAddressLocked is adding a permanent address, that address is
// promoted in place and its properties set to the properties provided. If the
// address already exists in any other state, then *tcpip.ErrDuplicateAddress is
// returned, regardless the kind of address that is being added.
//
// +checklocks:a.mu
func (a *AddressableEndpointState) addAndAcquireAddressLocked(addr tcpip.AddressWithPrefix, properties AddressProperties, kind AddressKind) (*addressState, tcpip.Error) {
	var permanent bool
	switch kind {
	case PermanentExpired:
		panic(fmt.Sprintf("cannot add address %s in PermanentExpired state", addr))
	case Permanent, PermanentTentative:
		permanent = true
	case Temporary:
	default:
		panic(fmt.Sprintf("unknown address kind: %d", kind))
	}
	// attemptAddToPrimary is false when the address is already in the primary
	// address list.
	attemptAddToPrimary := true
	addrState, ok := a.endpoints[addr.Address]
	if ok {
		if !permanent {
			// We are adding a non-permanent address but the address exists. No need
			// to go any further since we can only promote existing temporary/expired
			// addresses to permanent.
			return nil, &tcpip.ErrDuplicateAddress{}
		}

		addrState.mu.RLock()
		if addrState.refs.ReadRefs() == 0 {
			panic(fmt.Sprintf("found an address that should have been released (ref count == 0); address = %s", addrState.addr))
		}
		isPermanent := addrState.kind.IsPermanent()
		addrState.mu.RUnlock()

		if isPermanent {
			// We are adding a permanent address but a permanent address already
			// exists.
			return nil, &tcpip.ErrDuplicateAddress{}
		}

		// We now promote the address.
		for i, s := range a.primary {
			if s == addrState {
				switch properties.PEB {
				case CanBePrimaryEndpoint:
					// The address is already in the primary address list.
					attemptAddToPrimary = false
				case FirstPrimaryEndpoint:
					if i == 0 {
						// The address is already first in the primary address list.
						attemptAddToPrimary = false
					} else {
						a.primary = append(a.primary[:i], a.primary[i+1:]...)
					}
				case NeverPrimaryEndpoint:
					a.primary = append(a.primary[:i], a.primary[i+1:]...)
				default:
					panic(fmt.Sprintf("unrecognized primary endpoint behaviour = %d", properties.PEB))
				}
				break
			}
		}
		addrState.refs.IncRef()
	} else {
		addrState = &addressState{
			addressableEndpointState: a,
			addr:                     addr,
			temporary:                properties.Temporary,
			// Cache the subnet in addrState to avoid calls to addr.Subnet() as that
			// results in allocations on every call.
			subnet: addr.Subnet(),
		}
		addrState.refs.InitRefs()
		a.endpoints[addr.Address] = addrState
		// We never promote an address to temporary - it can only be added as such.
		// If we are actually adding a permanent address, it is promoted below.
		addrState.kind = Temporary
	}

	// At this point we have an address we are either promoting from an expired or
	// temporary address to permanent, promoting an expired address to temporary,
	// or we are adding a new temporary or permanent address.
	//
	// The address MUST be write locked at this point.
	addrState.mu.Lock()
	defer addrState.mu.Unlock()

	if permanent {
		if addrState.kind.IsPermanent() {
			panic(fmt.Sprintf("only non-permanent addresses should be promoted to permanent; address = %s", addrState.addr))
		}

		// Primary addresses are biased by 1.
		addrState.refs.IncRef()
		addrState.kind = kind
	}
	addrState.configType = properties.ConfigType
	lifetimes := properties.Lifetimes
	lifetimes.sanitize()
	addrState.lifetimes = lifetimes
	addrState.disp = properties.Disp

	if attemptAddToPrimary {
		switch properties.PEB {
		case NeverPrimaryEndpoint:
		case CanBePrimaryEndpoint:
			a.primary = append(a.primary, addrState)
		case FirstPrimaryEndpoint:
			if cap(a.primary) == len(a.primary) {
				a.primary = append([]*addressState{addrState}, a.primary...)
			} else {
				// Shift all the endpoints by 1 to make room for the new address at the
				// front. We could have just created a new slice but this saves
				// allocations when the slice has capacity for the new address.
				primaryCount := len(a.primary)
				a.primary = append(a.primary, nil)
				if n := copy(a.primary[1:], a.primary); n != primaryCount {
					panic(fmt.Sprintf("copied %d elements; expected = %d elements", n, primaryCount))
				}
				a.primary[0] = addrState
			}
		default:
			panic(fmt.Sprintf("unrecognized primary endpoint behaviour = %d", properties.PEB))
		}
	}

	addrState.notifyChangedLocked()
	return addrState, nil
}

// RemovePermanentAddress implements AddressableEndpoint.
func (a *AddressableEndpointState) RemovePermanentAddress(addr tcpip.Address) tcpip.Error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.removePermanentAddressLocked(addr)
}

// removePermanentAddressLocked is like RemovePermanentAddress but with locking
// requirements.
//
// +checklocks:a.mu
func (a *AddressableEndpointState) removePermanentAddressLocked(addr tcpip.Address) tcpip.Error {
	addrState, ok := a.endpoints[addr]
	if !ok {
		return &tcpip.ErrBadLocalAddress{}
	}

	return a.removePermanentEndpointLocked(addrState, AddressRemovalManualAction)
}

// RemovePermanentEndpoint removes the passed endpoint if it is associated with
// a and permanent.
func (a *AddressableEndpointState) RemovePermanentEndpoint(ep AddressEndpoint, reason AddressRemovalReason) tcpip.Error {
	addrState, ok := ep.(*addressState)
	if !ok || addrState.addressableEndpointState != a {
		return &tcpip.ErrInvalidEndpointState{}
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	return a.removePermanentEndpointLocked(addrState, reason)
}

// removePermanentAddressLocked is like RemovePermanentAddress but with locking
// requirements.
//
// +checklocks:a.mu
func (a *AddressableEndpointState) removePermanentEndpointLocked(addrState *addressState, reason AddressRemovalReason) tcpip.Error {
	if !addrState.GetKind().IsPermanent() {
		return &tcpip.ErrBadLocalAddress{}
	}

	addrState.remove(reason)
	a.decAddressRefLocked(addrState)
	return nil
}

// decAddressRef decrements the address's reference count and releases it once
// the reference count hits 0.
func (a *AddressableEndpointState) decAddressRef(addrState *addressState) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.decAddressRefLocked(addrState)
}

// decAddressRefLocked is like decAddressRef but with locking requirements.
//
// +checklocks:a.mu
func (a *AddressableEndpointState) decAddressRefLocked(addrState *addressState) {
	destroy := false
	addrState.refs.DecRef(func() {
		destroy = true
	})

	if !destroy {
		return
	}
	addrState.mu.Lock()
	defer addrState.mu.Unlock()
	// A non-expired permanent address must not have its reference count dropped
	// to 0.
	if addrState.kind.IsPermanent() {
		panic(fmt.Sprintf("permanent addresses should be removed through the AddressableEndpoint: addr = %s, kind = %d", addrState.addr, addrState.kind))
	}

	a.releaseAddressStateLocked(addrState)
}

// SetDeprecated implements stack.AddressableEndpoint.
func (a *AddressableEndpointState) SetDeprecated(addr tcpip.Address, deprecated bool) tcpip.Error {
	a.mu.RLock()
	defer a.mu.RUnlock()

	addrState, ok := a.endpoints[addr]
	if !ok {
		return &tcpip.ErrBadLocalAddress{}
	}
	addrState.SetDeprecated(deprecated)
	return nil
}

// SetLifetimes implements stack.AddressableEndpoint.
func (a *AddressableEndpointState) SetLifetimes(addr tcpip.Address, lifetimes AddressLifetimes) tcpip.Error {
	a.mu.RLock()
	defer a.mu.RUnlock()

	addrState, ok := a.endpoints[addr]
	if !ok {
		return &tcpip.ErrBadLocalAddress{}
	}
	addrState.SetLifetimes(lifetimes)
	return nil
}

// MainAddress implements AddressableEndpoint.
func (a *AddressableEndpointState) MainAddress() tcpip.AddressWithPrefix {
	a.mu.RLock()
	defer a.mu.RUnlock()

	ep := a.acquirePrimaryAddressRLocked(func(ep *addressState) bool {
		switch kind := ep.GetKind(); kind {
		case Permanent:
			return a.networkEndpoint.Enabled() || !a.options.HiddenWhileDisabled
		case PermanentTentative, PermanentExpired, Temporary:
			return false
		default:
			panic(fmt.Sprintf("unknown address kind: %d", kind))
		}
	})
	if ep == nil {
		return tcpip.AddressWithPrefix{}
	}
	addr := ep.AddressWithPrefix()
	// Note that when ep must have a ref count >=2, because its ref count
	// must be >=1 in order to be found and the ref count was incremented
	// when a reference was acquired. The only way for the ref count to
	// drop below 2 is for the endpoint to be removed, which requires a
	// write lock; so we're guaranteed to be able to decrement the ref
	// count and not need to remove the endpoint from a.primary.
	ep.decRefMustNotFree()
	return addr
}

// acquirePrimaryAddressRLocked returns an acquired primary address that is
// valid according to isValid.
//
// +checklocksread:a.mu
func (a *AddressableEndpointState) acquirePrimaryAddressRLocked(isValid func(*addressState) bool) *addressState {
	var deprecatedEndpoint *addressState
	for _, ep := range a.primary {
		if !isValid(ep) {
			continue
		}

		if !ep.Deprecated() {
			if ep.IncRef() {
				// ep is not deprecated, so return it immediately.
				//
				// If we kept track of a deprecated endpoint, decrement its reference
				// count since it was incremented when we decided to keep track of it.
				if deprecatedEndpoint != nil {
					// Note that when deprecatedEndpoint was found, its ref count
					// must have necessarily been >=1, and after incrementing it
					// must be >=2. The only way for the ref count to drop below 2 is
					// for the endpoint to be removed, which requires a write lock;
					// so we're guaranteed to be able to decrement the ref count
					// and not need to remove the endpoint from a.primary.
					deprecatedEndpoint.decRefMustNotFree()
				}

				return ep
			}
		} else if deprecatedEndpoint == nil && ep.IncRef() {
			// We prefer an endpoint that is not deprecated, but we keep track of
			// ep in case a doesn't have any non-deprecated endpoints.
			//
			// If we end up finding a more preferred endpoint, ep's reference count
			// will be decremented.
			deprecatedEndpoint = ep
		}
	}

	return deprecatedEndpoint
}

// AcquireAssignedAddressOrMatching returns an address endpoint that is
// considered assigned to the addressable endpoint.
//
// If the address is an exact match with an existing address, that address is
// returned. Otherwise, if f is provided, f is called with each address and
// the address that f returns true for is returned.
//
// If there is no matching address, a temporary address will be returned if
// allowTemp is true.
//
// Regardless how the address was obtained, it will be acquired before it is
// returned.
func (a *AddressableEndpointState) AcquireAssignedAddressOrMatching(localAddr tcpip.Address, f func(AddressEndpoint) bool, allowTemp bool, tempPEB PrimaryEndpointBehavior) AddressEndpoint {
	lookup := func() *addressState {
		if addrState, ok := a.endpoints[localAddr]; ok {
			if !addrState.IsAssigned(allowTemp) {
				return nil
			}

			if !addrState.IncRef() {
				panic(fmt.Sprintf("failed to increase the reference count for address = %s", addrState.addr))
			}

			return addrState
		}

		if f != nil {
			for _, addrState := range a.endpoints {
				if addrState.IsAssigned(allowTemp) && f(addrState) && addrState.IncRef() {
					return addrState
				}
			}
		}
		return nil
	}
	// Avoid exclusive lock on mu unless we need to add a new address.
	a.mu.RLock()
	ep := lookup()
	a.mu.RUnlock()

	if ep != nil {
		return ep
	}

	if !allowTemp {
		return nil
	}

	// Acquire state lock in exclusive mode as we need to add a new temporary
	// endpoint.
	a.mu.Lock()
	defer a.mu.Unlock()

	// Do the lookup again in case another goroutine added the address in the time
	// we released and acquired the lock.
	ep = lookup()
	if ep != nil {
		return ep
	}

	// Proceed to add a new temporary endpoint.
	addr := localAddr.WithPrefix()
	ep, err := a.addAndAcquireAddressLocked(addr, AddressProperties{PEB: tempPEB}, Temporary)
	if err != nil {
		// addAndAcquireAddressLocked only returns an error if the address is
		// already assigned but we just checked above if the address exists so we
		// expect no error.
		panic(fmt.Sprintf("a.addAndAcquireAddressLocked(%s, AddressProperties{PEB: %s}, false): %s", addr, tempPEB, err))
	}

	// From https://golang.org/doc/faq#nil_error:
	//
	// Under the covers, interfaces are implemented as two elements, a type T and
	// a value V.
	//
	// An interface value is nil only if the V and T are both unset, (T=nil, V is
	// not set), In particular, a nil interface will always hold a nil type. If we
	// store a nil pointer of type *int inside an interface value, the inner type
	// will be *int regardless of the value of the pointer: (T=*int, V=nil). Such
	// an interface value will therefore be non-nil even when the pointer value V
	// inside is nil.
	//
	// Since addAndAcquireAddressLocked returns a nil value with a non-nil type,
	// we need to explicitly return nil below if ep is (a typed) nil.
	if ep == nil {
		return nil
	}
	return ep
}

// AcquireAssignedAddress implements AddressableEndpoint.
func (a *AddressableEndpointState) AcquireAssignedAddress(localAddr tcpip.Address, allowTemp bool, tempPEB PrimaryEndpointBehavior) AddressEndpoint {
	return a.AcquireAssignedAddressOrMatching(localAddr, nil, allowTemp, tempPEB)
}

// AcquireOutgoingPrimaryAddress implements AddressableEndpoint.
func (a *AddressableEndpointState) AcquireOutgoingPrimaryAddress(remoteAddr tcpip.Address, allowExpired bool) AddressEndpoint {
	a.mu.Lock()
	defer a.mu.Unlock()

	ep := a.acquirePrimaryAddressRLocked(func(ep *addressState) bool {
		return ep.IsAssigned(allowExpired)
	})

	// From https://golang.org/doc/faq#nil_error:
	//
	// Under the covers, interfaces are implemented as two elements, a type T and
	// a value V.
	//
	// An interface value is nil only if the V and T are both unset, (T=nil, V is
	// not set), In particular, a nil interface will always hold a nil type. If we
	// store a nil pointer of type *int inside an interface value, the inner type
	// will be *int regardless of the value of the pointer: (T=*int, V=nil). Such
	// an interface value will therefore be non-nil even when the pointer value V
	// inside is nil.
	//
	// Since acquirePrimaryAddressLocked returns a nil value with a non-nil type,
	// we need to explicitly return nil below if ep is (a typed) nil.
	if ep == nil {
		return nil
	}

	return ep
}

// PrimaryAddresses implements AddressableEndpoint.
func (a *AddressableEndpointState) PrimaryAddresses() []tcpip.AddressWithPrefix {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var addrs []tcpip.AddressWithPrefix
	if a.options.HiddenWhileDisabled && !a.networkEndpoint.Enabled() {
		return addrs
	}
	for _, ep := range a.primary {
		switch kind := ep.GetKind(); kind {
		// Don't include tentative, expired or temporary endpoints
		// to avoid confusion and prevent the caller from using
		// those.
		case PermanentTentative, PermanentExpired, Temporary:
			continue
		case Permanent:
		default:
			panic(fmt.Sprintf("address %s has unknown kind %d", ep.AddressWithPrefix(), kind))
		}

		addrs = append(addrs, ep.AddressWithPrefix())
	}

	return addrs
}

// PermanentAddresses implements AddressableEndpoint.
func (a *AddressableEndpointState) PermanentAddresses() []tcpip.AddressWithPrefix {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var addrs []tcpip.AddressWithPrefix
	for _, ep := range a.endpoints {
		if !ep.GetKind().IsPermanent() {
			continue
		}

		addrs = append(addrs, ep.AddressWithPrefix())
	}

	return addrs
}

// Cleanup forcefully leaves all groups and removes all permanent addresses.
func (a *AddressableEndpointState) Cleanup() {
	a.mu.Lock()
	defer a.mu.Unlock()

	for _, ep := range a.endpoints {
		// removePermanentEndpointLocked returns *tcpip.ErrBadLocalAddress if ep is
		// not a permanent address.
		switch err := a.removePermanentEndpointLocked(ep, AddressRemovalInterfaceRemoved); err.(type) {
		case nil, *tcpip.ErrBadLocalAddress:
		default:
			panic(fmt.Sprintf("unexpected error from removePermanentEndpointLocked(%s): %s", ep.addr, err))
		}
	}
}

var _ AddressEndpoint = (*addressState)(nil)

// addressState holds state for an address.
type addressState struct {
	addressableEndpointState *AddressableEndpointState
	addr                     tcpip.AddressWithPrefix
	subnet                   tcpip.Subnet
	temporary                bool

	// Lock ordering (from outer to inner lock ordering):
	//
	// AddressableEndpointState.mu
	//   addressState.mu
	mu   addressStateRWMutex
	refs addressStateRefs
	// checklocks:mu
	kind AddressKind
	// checklocks:mu
	configType AddressConfigType
	// lifetimes holds this address' lifetimes.
	//
	// Invariant: if lifetimes.deprecated is true, then lifetimes.PreferredUntil
	// must be the zero value. Note that the converse does not need to be
	// upheld!
	//
	// checklocks:mu
	lifetimes AddressLifetimes
	// The enclosing mutex must be write-locked before calling methods on the
	// dispatcher.
	//
	// checklocks:mu
	disp AddressDispatcher
}

// AddressWithPrefix implements AddressEndpoint.
func (a *addressState) AddressWithPrefix() tcpip.AddressWithPrefix {
	return a.addr
}

// Subnet implements AddressEndpoint.
func (a *addressState) Subnet() tcpip.Subnet {
	return a.subnet
}

// GetKind implements AddressEndpoint.
func (a *addressState) GetKind() AddressKind {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.kind
}

// SetKind implements AddressEndpoint.
func (a *addressState) SetKind(kind AddressKind) {
	a.mu.Lock()
	defer a.mu.Unlock()

	prevKind := a.kind
	a.kind = kind
	if kind == PermanentExpired {
		a.notifyRemovedLocked(AddressRemovalManualAction)
	} else if prevKind != kind && a.addressableEndpointState.networkEndpoint.Enabled() {
		a.notifyChangedLocked()
	}
}

// notifyRemovedLocked notifies integrators of address removal.
//
// +checklocks:a.mu
func (a *addressState) notifyRemovedLocked(reason AddressRemovalReason) {
	if disp := a.disp; disp != nil {
		a.disp.OnRemoved(reason)
		a.disp = nil
	}
}

func (a *addressState) remove(reason AddressRemovalReason) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.kind = PermanentExpired
	a.notifyRemovedLocked(reason)
}

// IsAssigned implements AddressEndpoint.
func (a *addressState) IsAssigned(allowExpired bool) bool {
	switch kind := a.GetKind(); kind {
	case PermanentTentative:
		return false
	case PermanentExpired:
		return allowExpired
	case Permanent, Temporary:
		return true
	default:
		panic(fmt.Sprintf("address %s has unknown kind %d", a.AddressWithPrefix(), kind))
	}
}

// IncRef implements AddressEndpoint.
func (a *addressState) IncRef() bool {
	return a.refs.TryIncRef()
}

// DecRef implements AddressEndpoint.
func (a *addressState) DecRef() {
	a.addressableEndpointState.decAddressRef(a)
}

// decRefMustNotFree decreases the reference count with the guarantee that the
// reference count will be greater than 0 after the decrement.
//
// Panics if the ref count is less than 2 after acquiring the lock in this
// function.
func (a *addressState) decRefMustNotFree() {
	a.refs.DecRef(func() {
		panic(fmt.Sprintf("cannot decrease addressState %s without freeing the endpoint", a.addr))
	})
}

// ConfigType implements AddressEndpoint.
func (a *addressState) ConfigType() AddressConfigType {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.configType
}

// notifyChangedLocked notifies integrators of address property changes.
//
// +checklocks:a.mu
func (a *addressState) notifyChangedLocked() {
	if a.disp == nil {
		return
	}

	state := AddressDisabled
	if a.addressableEndpointState.networkEndpoint.Enabled() {
		switch a.kind {
		case Permanent:
			state = AddressAssigned
		case PermanentTentative:
			state = AddressTentative
		case Temporary, PermanentExpired:
			return
		default:
			panic(fmt.Sprintf("unrecognized address kind = %d", a.kind))
		}
	}

	a.disp.OnChanged(a.lifetimes, state)
}

// SetDeprecated implements AddressEndpoint.
func (a *addressState) SetDeprecated(d bool) {
	a.mu.Lock()
	defer a.mu.Unlock()

	var changed bool
	if a.lifetimes.Deprecated != d {
		a.lifetimes.Deprecated = d
		changed = true
	}
	if d {
		a.lifetimes.PreferredUntil = tcpip.MonotonicTime{}
	}
	if changed {
		a.notifyChangedLocked()
	}
}

// Deprecated implements AddressEndpoint.
func (a *addressState) Deprecated() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.lifetimes.Deprecated
}

// SetLifetimes implements AddressEndpoint.
func (a *addressState) SetLifetimes(lifetimes AddressLifetimes) {
	a.mu.Lock()
	defer a.mu.Unlock()

	lifetimes.sanitize()

	var changed bool
	if a.lifetimes != lifetimes {
		changed = true
	}
	a.lifetimes = lifetimes
	if changed {
		a.notifyChangedLocked()
	}
}

// Lifetimes implements AddressEndpoint.
func (a *addressState) Lifetimes() AddressLifetimes {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.lifetimes
}

// Temporary implements AddressEndpoint.
func (a *addressState) Temporary() bool {
	return a.temporary
}

// RegisterDispatcher implements AddressEndpoint.
func (a *addressState) RegisterDispatcher(disp AddressDispatcher) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if disp != nil {
		a.disp = disp
		a.notifyChangedLocked()
	}
}
