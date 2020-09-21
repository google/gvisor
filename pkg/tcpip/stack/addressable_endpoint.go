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

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
)

// AddressableEndpoint is an endpoint that supports addressing.
//
// An endpoint is considered to support addressing when the endpoint associates
// itself with an identifier (address) that is used to filter incoming packets
// before processing them. That is, if an incoming packet does not hold an
// address an endpoint is associated with, the endpoint should not process it.
type AddressableEndpoint interface {
	// AddPermanentAddress adds the passed permanent address.
	//
	// Returns the AddressEndpoint for the added address without acquiring it.
	AddPermanentAddress(addr tcpip.AddressWithPrefix, peb PrimaryEndpointBehavior, configType AddressConfigType, deprecated bool) (AddressEndpoint, *tcpip.Error)

	// RemovePermanentAddress removes the passed address if it is a permanent
	// address.
	RemovePermanentAddress(addr tcpip.Address) *tcpip.Error

	// AcquireAssignedAddress returns an assigned endpoint for the specified
	// local address, optionally creating a temporary endpoint if requested.
	//
	// The returned endpoint's reference count will be incremented.
	//
	// Returns nil if the specified address is not local to this endpoint.
	AcquireAssignedAddress(localAddr tcpip.Address, allowTemp bool, tempPEB PrimaryEndpointBehavior) AddressEndpoint

	// AcquirePrimaryAddress returns a primary endpoint to use when communicating
	// with the passed remote address.
	//
	// The returned endpoint's reference count will be incremented.
	//
	// Returns nil if a primary endpoint is not available.
	AcquirePrimaryAddress(remoteAddr tcpip.Address, spoofingOrPromiscuous bool) AddressEndpoint

	// PrimaryAddresses returns the primary addresses.
	PrimaryAddresses() []tcpip.AddressWithPrefix

	// AllPermanentAddresses returns all the permanent addresses.
	AllPermanentAddresses() []tcpip.AddressWithPrefix

	// RemoveAllPermanentAddresses removes all permanent addresses.
	RemoveAllPermanentAddresses() *tcpip.Error
}

// PrimaryEndpointBehavior is an enumeration of an AddressEndpoint's primary
// behavior.
type PrimaryEndpointBehavior int

const (
	// CanBePrimaryEndpoint indicates the endpoint can be used as a primary
	// endpoint for new connections with no local address. This is the
	// default when calling NIC.AddAddress.
	CanBePrimaryEndpoint PrimaryEndpointBehavior = iota

	// FirstPrimaryEndpoint indicates the endpoint should be the first
	// primary endpoint considered. If there are multiple endpoints with
	// this behavior, the most recently-added one will be first.
	FirstPrimaryEndpoint

	// NeverPrimaryEndpoint indicates the endpoint should never be a
	// primary endpoint.
	NeverPrimaryEndpoint
)

// AddressConfigType is the method used to add an address.
type AddressConfigType int32

const (
	// AddressConfigStatic is a statically configured address endpoint that was
	// added by some user-specified action (adding an explicit address, joining a
	// multicast group).
	AddressConfigStatic AddressConfigType = iota

	// AddressConfigSlaac is an address endpoint added by SLAAC, as per RFC 4862
	// section 5.5.3.
	AddressConfigSlaac

	// AddressConfigSlaacTemp is a temporary address endpoint added by SLAAC as
	// per RFC 4941. Temporary SLAAC addresses are short-lived and are not
	// to be valid (or preferred) forever; hence the term temporary.
	AddressConfigSlaacTemp
)

// AddressEndpoint is an endpoint representing an address assigned to an
// AddressableEndpoint.
type AddressEndpoint interface {
	// AddressWithPrefix returns the endpoint's address.
	AddressWithPrefix() tcpip.AddressWithPrefix

	// IsAssigned returns whether or not th endpoint is considered bound
	// to its AddressableEndpoint.
	IsAssigned(spoofingOrPromiscuous bool) bool

	// GetKind returns the AddressKind for this endpoint.
	GetKind() AddressKind

	// SetKind sets the AddressKind for this endpoint.
	SetKind(AddressKind)

	// IncRef increments this endpoint's reference count.
	//
	// Returns true if it was successfully incremented. If it returns false, then
	// the endpoint is considered expired and should no longer be used.
	IncRef() bool

	// DecRef decrements this endpoint's reference count.
	DecRef()

	// ConfigType returns the method used to add the address.
	ConfigType() AddressConfigType

	// Deprecated returns whether or not this endpoint is deprecated.
	Deprecated() bool

	// SetDeprecated sets this endpoint's deprecated status.
	SetDeprecated(bool)
}

// AddressKind is the kind of of an address.
//
// See the values of AddressKind for more details.
type AddressKind int32

const (
	// PermanentTentative is a permanent address endpoint that is not yet
	// considered to be fully bound to an interface in the traditional
	// sense. That is, the address is associated with a NIC, but packets
	// destined to the address MUST NOT be accepted and MUST be silently
	// dropped, and the address MUST NOT be used as a source address for
	// outgoing packets. For IPv6, addresses will be of this kind until
	// NDP's Duplicate Address Detection has resolved, or be deleted if
	// the process results in detecting a duplicate address.
	PermanentTentative AddressKind = iota

	// Permanent is a permanent endpoint (vs. a temporary one) assigned to the
	// NIC. Its reference count is biased by 1 to avoid removal when no route
	// holds a reference to it. It is removed by explicitly removing the address
	// from the NIC.
	Permanent

	// PermanentExpired is a permanent endpoint that had its address removed from
	// the NIC, and it is waiting to be removed once no references to it are held.
	//
	// If the address is re-added before the endpoint is removed, its type
	// changes back to Permanent.
	PermanentExpired

	// Temporary is an endpoint, created on a one-off basis to temporarily
	// consider the NIC bound an an address that it is not explictiy bound to
	// (such as a permanent address). Its reference count must not be biased by 1
	// so that the address is removed immediately when references to it are no
	// longer held.
	//
	// A temporary endpoint may be promoted to permanent if the address is added
	// permanently.
	Temporary
)

// IsPermanent returns true if the AddressKind represents a permanent address.
func (k AddressKind) IsPermanent() bool {
	switch k {
	case Permanent, PermanentTentative:
		return true
	case Temporary, PermanentExpired:
		return false
	default:
		panic(fmt.Sprintf("unrecognized address kind = %d", k))
	}
}

// NewAddressableEndpointState returns an AddressableEndpointState.
func NewAddressableEndpointState() *AddressableEndpointState {
	a := &AddressableEndpointState{}
	a.mu.endpoints = make(map[tcpip.Address]*addressState)
	return a
}

var _ AddressableEndpoint = (*AddressableEndpointState)(nil)

// AddressableEndpointState is an implementation of an AddressableEndpoint.
type AddressableEndpointState struct {
	mu struct {
		sync.RWMutex

		endpoints map[tcpip.Address]*addressState
		primary   []*addressState
	}
}

// ReadonlyAddressEndpointMap provides read-only access to an AddressEndpoint
// map.
//
// ReadonlyAddressEndpointMap MUST be released when the owner is done with it.
type ReadonlyAddressEndpointMap struct {
	inner *AddressableEndpointState
}

// Lookup returns the AddressEndpoint for addr.
//
// Returns nil if no endpoint exists.
func (m *ReadonlyAddressEndpointMap) Lookup(addr tcpip.Address) AddressEndpoint {
	ep := m.inner.mu.endpoints[addr]
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
	// To make sure callers can reliably compare the returned value with nil, we
	// explicitly return a nil value if the endpoint is nil.
	if ep == nil {
		return nil
	}
	return ep
}

// ForEach calls f for each address/endpoint pair.
func (m *ReadonlyAddressEndpointMap) ForEach(f func(tcpip.Address, AddressEndpoint) bool) {
	for a, s := range m.inner.mu.endpoints {
		if !f(a, s) {
			return
		}
	}
}

// Release releases resources.
//
// This method MUST be called when the owner is done with m.
func (m *ReadonlyAddressEndpointMap) Release() {
	m.inner.mu.RUnlock()
}

// ReadonlyAllEndpoints returns a readonly reference to the map of endpoints.
//
// The returned ReadonlyAddressEndpointMap MUST be released before calling back
// into a.
func (a *AddressableEndpointState) ReadonlyAllEndpoints() ReadonlyAddressEndpointMap {
	a.mu.RLock()
	return ReadonlyAddressEndpointMap{inner: a}
}

// ForEachPrimaryEndpoint calls the specified function for each primary
// endpoint.
func (a *AddressableEndpointState) ForEachPrimaryEndpoint(f func(AddressEndpoint)) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	for _, e := range a.mu.primary {
		f(e)
	}
}

func (a *AddressableEndpointState) releaseAddressState(addrState *addressState) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.releaseAddressStateLocked(addrState)
}

// releaseAddressState removes addrState from s's address state (primary and endpoints list).
//
// Preconditions: a.mu must be write locked.
func (a *AddressableEndpointState) releaseAddressStateLocked(addrState *addressState) {
	oldPrimary := a.mu.primary
	for i, s := range a.mu.primary {
		if s == addrState {
			a.mu.primary = append(a.mu.primary[:i], a.mu.primary[i+1:]...)
			oldPrimary[len(oldPrimary)-1] = nil
			break
		}
	}
	delete(a.mu.endpoints, addrState.addr.Address)
}

// AddPermanentAddress implements AddressableEndpoint.
func (a *AddressableEndpointState) AddPermanentAddress(addr tcpip.AddressWithPrefix, peb PrimaryEndpointBehavior, configType AddressConfigType, deprecated bool) (AddressEndpoint, *tcpip.Error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.addAddressLocked(addr, peb, configType, deprecated, true /* permanent */)
}

// AddAndAcquireTemporaryAddress adds a temporary address.
//
// The temporary address's endpoint will be acquired and returned.
func (a *AddressableEndpointState) AddAndAcquireTemporaryAddress(addr tcpip.AddressWithPrefix, peb PrimaryEndpointBehavior) (AddressEndpoint, *tcpip.Error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.addAddressLocked(addr, peb, AddressConfigStatic, false /* deprecated */, false /* permanent */)
}

// addAddressLocked is like AddAddress but with locking requirments.
//
// Precondition: a.mu must be write locked.
func (a *AddressableEndpointState) addAddressLocked(addr tcpip.AddressWithPrefix, peb PrimaryEndpointBehavior, configType AddressConfigType, deprecated, permanent bool) (AddressEndpoint, *tcpip.Error) {
	addToPrimary := func(addrState *addressState, peb PrimaryEndpointBehavior) {
		switch peb {
		case CanBePrimaryEndpoint:
			a.mu.primary = append(a.mu.primary, addrState)
		case FirstPrimaryEndpoint:
			a.mu.primary = append([]*addressState{addrState}, a.mu.primary...)
		}
	}

	if addrState, ok := a.mu.endpoints[addr.Address]; ok {
		// Address already exists.
		if !permanent {
			return nil, tcpip.ErrDuplicateAddress
		}

		addrState.mu.Lock()
		if addrState.mu.kind.IsPermanent() {
			addrState.mu.Unlock()
			return nil, tcpip.ErrDuplicateAddress
		}

		if addrState.mu.refs != 0 {
			addrState.mu.refs++
			addrState.mu.kind = Permanent
			addrState.mu.deprecated = deprecated
			addrState.mu.configType = configType
			addrState.mu.Unlock()

			for i, s := range a.mu.primary {
				if s == addrState {
					switch peb {
					case CanBePrimaryEndpoint:
						return addrState, nil
					case FirstPrimaryEndpoint:
						if i == 0 {
							return addrState, nil
						}
						a.mu.primary = append(a.mu.primary[:i], a.mu.primary[i+1:]...)
					case NeverPrimaryEndpoint:
						a.mu.primary = append(a.mu.primary[:i], a.mu.primary[i+1:]...)
						return addrState, nil
					}
				}
			}

			addToPrimary(addrState, peb)
			return addrState, nil
		}

		a.releaseAddressStateLocked(addrState)
		addrState.mu.Unlock()
	}

	addrState := &addressState{
		networkState: a,
		addr:         addr,
	}
	addrState.mu.refs = 1
	if permanent {
		addrState.mu.kind = Permanent
	} else {
		addrState.mu.kind = Temporary
	}
	addrState.mu.configType = configType
	addrState.mu.deprecated = deprecated

	a.mu.endpoints[addr.Address] = addrState
	addToPrimary(addrState, peb)

	return addrState, nil
}

// RemovePermanentAddress implements AddressableEndpoint.
func (a *AddressableEndpointState) RemovePermanentAddress(addr tcpip.Address) *tcpip.Error {
	a.mu.Lock()
	defer a.mu.Unlock()

	addrState, ok := a.mu.endpoints[addr]
	if !ok {
		return tcpip.ErrBadLocalAddress
	}

	return a.removePermanentEndpointLocked(addrState)
}

// RemovePermanentEndpoint removes the passed endpoint if it is associated with
// a and permanent.
func (a *AddressableEndpointState) RemovePermanentEndpoint(ep AddressEndpoint) *tcpip.Error {
	addrState, ok := ep.(*addressState)
	if !ok || addrState.networkState != a {
		return tcpip.ErrInvalidEndpointState
	}

	return a.removePermanentEndpointLocked(addrState)
}

// removePermanentAddressLocked is like RemovePermanentAddress but with locking
// requirements.
//
// Precondition: a.mu must be write locked.
func (a *AddressableEndpointState) removePermanentEndpointLocked(addrState *addressState) *tcpip.Error {
	if !addrState.GetKind().IsPermanent() {
		return tcpip.ErrBadLocalAddress
	}

	addrState.SetKind(PermanentExpired)
	a.decAddressRefLocked(addrState)
	return nil
}

// decAddressRefLocked decremeents the reference count for addrState and
// releases it from s if addrState's reference count reaches 0.
func (a *AddressableEndpointState) decAddressRefLocked(addrState *addressState) {
	if addrState.decRef() {
		a.releaseAddressStateLocked(addrState)
	}
}

// AcquireAssignedAddress implements AddressableEndpoint.
func (a *AddressableEndpointState) AcquireAssignedAddress(localAddr tcpip.Address, allowTemp bool, tempPEB PrimaryEndpointBehavior) AddressEndpoint {
	a.mu.Lock()
	defer a.mu.Unlock()

	if r, ok := a.mu.endpoints[localAddr]; ok {
		if !r.IsAssigned(allowTemp) {
			return nil
		}

		if r.IncRef() {
			return r
		}

		a.releaseAddressStateLocked(r)
	}

	if !allowTemp {
		return nil
	}

	addr := tcpip.AddressWithPrefix{
		Address:   localAddr,
		PrefixLen: len(localAddr) * 8,
	}
	r, err := a.addAddressLocked(addr, tempPEB, AddressConfigStatic, false /* deprecated */, false /* permanent */)
	if err != nil {
		// AddAddress only returns an error if the address is already assigned,
		// but we just checked above if the address exists so we expect no error.
		panic(fmt.Sprintf("a.addAddressLocked(%s, %d, %d, false, false): %s", addr, tempPEB, AddressConfigStatic, err))
	}
	return r
}

// AcquirePrimaryAddress implements AddressableEndpoint.
func (a *AddressableEndpointState) AcquirePrimaryAddress(remoteAddr tcpip.Address, spoofingOrPromiscuous bool) AddressEndpoint {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var deprecatedEndpoint *addressState
	for _, r := range a.mu.primary {
		if !r.IsAssigned(spoofingOrPromiscuous) {
			continue
		}

		if !r.Deprecated() {
			if r.IncRef() {
				// r is not deprecated, so return it immediately.
				//
				// If we kept track of a deprecated endpoint, decrement its reference
				// count since it was incremented when we decided to keep track of it.
				if deprecatedEndpoint != nil {
					a.decAddressRefLocked(deprecatedEndpoint)
					deprecatedEndpoint = nil
				}

				return r
			}
		} else if deprecatedEndpoint == nil && r.IncRef() {
			// We prefer an endpoint that is not deprecated, but we keep track of r in
			// case n doesn't have any non-deprecated endpoints.
			//
			// If we end up finding a more preferred endpoint, r's reference count
			// will be decremented when such an endpoint is found.
			deprecatedEndpoint = r
		}
	}

	// n doesn't have any valid non-deprecated endpoints, so return
	// deprecatedEndpoint (which may be nil if n doesn't have any valid deprecated
	// endpoints either).
	if deprecatedEndpoint == nil {
		return nil
	}
	return deprecatedEndpoint
}

// PrimaryAddresses implements AddressableEndpoint.
func (a *AddressableEndpointState) PrimaryAddresses() []tcpip.AddressWithPrefix {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var addrs []tcpip.AddressWithPrefix
	for _, r := range a.mu.primary {
		// Don't include tentative, expired or temporary endpoints
		// to avoid confusion and prevent the caller from using
		// those.
		switch r.GetKind() {
		case PermanentTentative, PermanentExpired, Temporary:
			continue
		}

		addrs = append(addrs, r.AddressWithPrefix())
	}

	return addrs
}

// AllPermanentAddresses implements AddressableEndpoint.
func (a *AddressableEndpointState) AllPermanentAddresses() []tcpip.AddressWithPrefix {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var addrs []tcpip.AddressWithPrefix
	for _, r := range a.mu.endpoints {
		// Don't include tentative, expired or temporary endpoints
		// to avoid confusion and prevent the caller from using
		// those.
		switch r.GetKind() {
		case PermanentExpired, Temporary:
			continue
		}

		addrs = append(addrs, r.AddressWithPrefix())
	}

	return addrs
}

// RemoveAllPermanentAddresses implements AddressableEndpoint.
func (a *AddressableEndpointState) RemoveAllPermanentAddresses() *tcpip.Error {
	a.mu.Lock()
	defer a.mu.Unlock()

	var err *tcpip.Error
	for _, r := range a.mu.endpoints {
		if r.GetKind().IsPermanent() {
			if tempErr := a.removePermanentEndpointLocked(r); tempErr != nil && err == nil {
				err = tempErr
			}
		}
	}
	return err
}

var _ AddressEndpoint = (*addressState)(nil)

// addressState holds state for an address.
type addressState struct {
	networkState *AddressableEndpointState
	addr         tcpip.AddressWithPrefix

	mu struct {
		sync.RWMutex

		refs       uint32
		kind       AddressKind
		configType AddressConfigType
		deprecated bool
	}
}

// AddressWithPrefix implements AddressEndpoint.
func (a *addressState) AddressWithPrefix() tcpip.AddressWithPrefix {
	return a.addr
}

// GetKind implements AddressEndpoint.
func (a *addressState) GetKind() AddressKind {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.mu.kind
}

// SetKind implements AddressEndpoint.
func (a *addressState) SetKind(kind AddressKind) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.mu.kind = kind
}

// IsAssigned implements AddressEndpoint.
func (a *addressState) IsAssigned(spoofingOrPromiscuous bool) bool {
	switch a.GetKind() {
	case PermanentTentative:
		return false
	case PermanentExpired:
		return spoofingOrPromiscuous
	default:
		return true
	}
}

// IncRef implements AddressEndpoint.
func (a *addressState) IncRef() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.mu.refs == 0 {
		return false
	}

	a.mu.refs++
	return true
}

// DecRef implements AddressEndpoint.
func (a *addressState) DecRef() {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.decRefLocked() {
		return
	}

	if a.mu.kind.IsPermanent() {
		panic(fmt.Sprintf("permanent addresses should be removed through the AddressableEndpoint: addr = %s, kind = %d", a.addr, a.mu.kind))
	}

	a.networkState.releaseAddressState(a)
}

// decRef decrements the reference count.
//
// Returns true if the endpoint needs to be released.
func (a *addressState) decRef() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.decRefLocked()
}

// defRefLocked is like decRef but with locking requirements.
//
// Precondition: a.mu must be write locked.
func (a *addressState) decRefLocked() bool {
	if a.mu.refs == 0 {
		return false
	}

	a.mu.refs--
	return a.mu.refs == 0
}

// ConfigType implements AddressEndpoint.
func (a *addressState) ConfigType() AddressConfigType {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.mu.configType
}

// SetDeprecated implements AddressEndpoint.
func (a *addressState) SetDeprecated(d bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.mu.deprecated = d
}

// Deprecated implements AddressEndpoint.
func (a *addressState) Deprecated() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.mu.deprecated
}
