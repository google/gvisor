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
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
)

// AddressableEndpoint is an endpoint that supports addressing.
type AddressableEndpoint interface {
	// AddAddress adds the specifid address with the given options.
	//
	// Returns a AddressEndpoint for the added address with a ref count
	// of 1. If a Temporary addrss was added, it must be used without incrmenting
	// the AddressEndpoint's ref count. Other endpoints' ref count will
	// need to be incremented.
	AddAddress(addr tcpip.AddressWithPrefix, opts AddAddressOptions) (AddressEndpoint, *tcpip.Error)

	// RemoveAddress removes a permanent address.
	RemoveAddress(addr tcpip.Address) *tcpip.Error

	// HasAddress returns true if the endpoint has the specified permanent
	// address.
	HasAddress(addr tcpip.Address) bool

	// PrimaryEndpoints returns all the primary endpoints.
	PrimaryEndpoints() []AddressEndpoint

	// AllEndpoints returns all the endpoints.
	AllEndpoints() []AddressEndpoint

	// GetEndpoint returns an endpoint for the specified local address.
	//
	// The returned endpoint's reference count will not be incremnted.
	//
	// Returns nil if the specified address is not local to this endpoint.
	GetEndpoint(localAddr tcpip.Address) AddressEndpoint

	// GetAssignedEndpoint returns an assigned endpoint for the specified local
	// address, optionally creating a temporary endpoint if requested.
	//
	// The returned endpoint's reference count will be incremented.
	//
	// Returns nil if the specified address is not local to this endpoint.
	GetAssignedEndpoint(localAddr tcpip.Address, allowAnyInSubnet, allowTemp bool, tempPEB PrimaryEndpointBehavior) AddressEndpoint

	// PrimaryEndpoint returns a primary endpooint to use when communicating with
	// the specified remote address.
	//
	// The returned endpoint's reference count will be incremented.
	//
	// Returns nil if a primary endpoint is not available.
	PrimaryEndpoint(remoteAddr tcpip.Address, spoofingOrPromiscuous bool) AddressEndpoint

	// PrimaryAddresses returns the primary addresses.
	PrimaryAddresses() []tcpip.AddressWithPrefix

	// AllAddresses returns all the addresses.
	AllAddresses() []tcpip.AddressWithPrefix

	// RemoveAllAddresses removes all permanent addresses.
	RemoveAllAddresses() *tcpip.Error
}

// AddressConfigType is the way an address was configured.
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

// AddAddressOptions are options when adding an address.
type AddAddressOptions struct {
	Deprecated bool
	ConfigType AddressConfigType
	Kind       AddressKind
	PEB        PrimaryEndpointBehavior
}

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
	//
	// If it returns true, then the endpoint has been released and must no longer
	// be used.
	DecRef() bool

	// ConfigType returns the method used to add this endpoint to its
	// AddressableEndpoint.
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

// NewAddressableEndpoint returns an AddressableEndpoint that is protected by a
// lock.
//
// Useful when specialization of an AddressableEndpoint is not required.
func NewAddressableEndpoint() AddressableEndpoint {
	l := &lockedAddressableEndpointState{}
	l.mu.ep = addressableEndpointState{
		lock:      &l.mu,
		endpoints: make(map[tcpip.Address]*addressState),
	}
	return l
}

// NewAddressableEndpointWithLock returns an AddressableEndpoint that requires
// the specified lock to be held before calling any methods on itself.
//
// The returned AddressableEndpoint will not obtain the lock before doing any
// work.
//
// Useful when an implementation may want to specialize some functions of the
// AddressableEndpoint.
func NewAddressableEndpointWithLock(lock sync.Locker) AddressableEndpoint {
	return &addressableEndpointState{
		lock:      lock,
		endpoints: make(map[tcpip.Address]*addressState),
	}
}

var _ AddressableEndpoint = (*lockedAddressableEndpointState)(nil)

// lockedAddressableEndpointState is an implementation of AddressableEndpoint
// that protects an inner AddressableEndpoint with a mutex.
type lockedAddressableEndpointState struct {
	mu struct {
		sync.RWMutex
		ep addressableEndpointState
	}
}

// AddAddress implements AddressableEndpoint.
func (e *lockedAddressableEndpointState) AddAddress(addr tcpip.AddressWithPrefix, opts AddAddressOptions) (AddressEndpoint, *tcpip.Error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.mu.ep.AddAddress(addr, opts)
}

// RemoveAddress implements AddressableEndpoint.
func (e *lockedAddressableEndpointState) RemoveAddress(addr tcpip.Address) *tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.mu.ep.RemoveAddress(addr)
}

// HasAddress implements AddressableEndpoint.
func (e *lockedAddressableEndpointState) HasAddress(addr tcpip.Address) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.mu.ep.HasAddress(addr)
}

// PrimaryEndpoints implements AddressableEndpoint.
func (e *lockedAddressableEndpointState) PrimaryEndpoints() []AddressEndpoint {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.mu.ep.PrimaryEndpoints()
}

// AllEndpoints implements AddressableEndpoint.
func (e *lockedAddressableEndpointState) AllEndpoints() []AddressEndpoint {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.mu.ep.AllEndpoints()
}

// GetEndpoint implements AddressableEndpoint.
func (e *lockedAddressableEndpointState) GetEndpoint(localAddr tcpip.Address) AddressEndpoint {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.mu.ep.GetEndpoint(localAddr)
}

// GetAssignedEndpoint implements AddressableEndpoint.
func (e *lockedAddressableEndpointState) GetAssignedEndpoint(localAddr tcpip.Address, allowAnyInSubnet, allowTemp bool, tempPEB PrimaryEndpointBehavior) AddressEndpoint {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.mu.ep.GetAssignedEndpoint(localAddr, allowAnyInSubnet, allowTemp, tempPEB)
}

// PrimaryEndpoint implements AddressableEndpoint.
func (e *lockedAddressableEndpointState) PrimaryEndpoint(remoteAddr tcpip.Address, spoofingOrPromiscuous bool) AddressEndpoint {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.mu.ep.PrimaryEndpoint(remoteAddr, spoofingOrPromiscuous)
}

// PrimaryAddresses implements AddressableEndpoint.
func (e *lockedAddressableEndpointState) PrimaryAddresses() []tcpip.AddressWithPrefix {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.mu.ep.PrimaryAddresses()
}

// AllAddresses implements AddressableEndpoint.
func (e *lockedAddressableEndpointState) AllAddresses() []tcpip.AddressWithPrefix {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.mu.ep.AllAddresses()
}

// RemoveAllAddresses implements AddressableEndpoint.
func (e *lockedAddressableEndpointState) RemoveAllAddresses() *tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.mu.ep.RemoveAllAddresses()
}

var _ AddressableEndpoint = (*addressableEndpointState)(nil)

// addressableEndpointState is an implementation of an AddressableEndpoint that
// does not perform any locking before doing work defined by
// AddressableEndpoint.
type addressableEndpointState struct {
	lock      sync.Locker
	endpoints map[tcpip.Address]*addressState
	primary   []*addressState
}

func (s *addressableEndpointState) takeLockAndReleaseAddressState(addrState *addressState) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.releaseAddressState(addrState)
}

// releaseAddressState removes addrState from s's address state (primary and endpoints list).
func (s *addressableEndpointState) releaseAddressState(addrState *addressState) {
	oldPrimary := s.primary
	for i, a := range s.primary {
		if a == addrState {
			s.primary = append(s.primary[:i], s.primary[i+1:]...)
			oldPrimary[len(oldPrimary)-1] = nil
			break
		}
	}
	delete(s.endpoints, addrState.addr.Address)
}

// AddAddress implements AddressableEndpoint.
func (s *addressableEndpointState) AddAddress(addr tcpip.AddressWithPrefix, opts AddAddressOptions) (AddressEndpoint, *tcpip.Error) {
	addToPrimary := func(addrState *addressState, peb PrimaryEndpointBehavior) {
		switch peb {
		case CanBePrimaryEndpoint:
			s.primary = append(s.primary, addrState)
		case FirstPrimaryEndpoint:
			s.primary = append([]*addressState{addrState}, s.primary...)
		}
	}

	if addrState, ok := s.endpoints[addr.Address]; ok {
		// Address already exists.
		if opts.Kind != Permanent {
			return nil, tcpip.ErrDuplicateAddress
		}

		switch addrState.GetKind() {
		case PermanentTentative, Permanent:
			return nil, tcpip.ErrDuplicateAddress
		case PermanentExpired, Temporary:
			if addrState.IncRef() {
				addrState.SetKind(Permanent)
				addrState.deprecated = opts.Deprecated
				addrState.configType = opts.ConfigType

				for i, a := range s.primary {
					if a == addrState {
						switch opts.PEB {
						case CanBePrimaryEndpoint:
							return addrState, nil
						case FirstPrimaryEndpoint:
							if i == 0 {
								return addrState, nil
							}
							s.primary = append(s.primary[:i], s.primary[i+1:]...)
						case NeverPrimaryEndpoint:
							s.primary = append(s.primary[:i], s.primary[i+1:]...)
							return addrState, nil
						}
					}
				}

				addToPrimary(addrState, opts.PEB)

				return addrState, nil
			}

			s.releaseAddressState(addrState)
		}
	}

	addrState := &addressState{
		networkState: s,
		addr:         addr,
		refs:         1,
		kind:         opts.Kind,
		configType:   opts.ConfigType,
		deprecated:   opts.Deprecated,
	}

	s.endpoints[addr.Address] = addrState
	addToPrimary(addrState, opts.PEB)

	return addrState, nil
}

// RemoveAddress implements AddressableEndpoint.
func (s *addressableEndpointState) RemoveAddress(addr tcpip.Address) *tcpip.Error {
	addrState, ok := s.endpoints[addr]
	if !ok {
		return tcpip.ErrBadLocalAddress
	}

	if kind := addrState.GetKind(); kind != Permanent && kind != PermanentTentative {
		return tcpip.ErrBadLocalAddress
	}

	addrState.SetKind(PermanentExpired)
	s.decAddressRef(addrState)

	return nil
}

func (s *addressableEndpointState) decAddressRef(addrState *addressState) {
	if addrState.decRef() {
		s.releaseAddressState(addrState)
	}
}

// HasAddress implements AddressableEndpoint.
func (s *addressableEndpointState) HasAddress(addr tcpip.Address) bool {
	addrState, ok := s.endpoints[addr]
	if !ok {
		return false
	}

	kind := addrState.GetKind()
	return kind == Permanent || kind == PermanentTentative
}

// AllEndpoints implements AddressableEndpoint.
func (s *addressableEndpointState) AllEndpoints() []AddressEndpoint {
	eps := make([]AddressEndpoint, 0, len(s.endpoints))
	for _, e := range s.endpoints {
		eps = append(eps, e)
	}
	return eps
}

// PrimaryEndpoints implements AddressableEndpoint.
func (s *addressableEndpointState) PrimaryEndpoints() []AddressEndpoint {
	eps := make([]AddressEndpoint, 0, len(s.primary))
	for _, e := range s.primary {
		eps = append(eps, e)
	}
	return eps
}

// GetEndpoint implements AddressableEndpoint.
func (s *addressableEndpointState) GetEndpoint(localAddr tcpip.Address) AddressEndpoint {
	if r, ok := s.endpoints[localAddr]; ok && r.GetKind() != PermanentExpired {
		return r
	}

	return nil
}

// GetAssignedEndpoint implements AddressableEndpoint.
func (s *addressableEndpointState) GetAssignedEndpoint(localAddr tcpip.Address, allowAnyInSubnet, allowTemp bool, tempPEB PrimaryEndpointBehavior) AddressEndpoint {
	if r, ok := s.endpoints[localAddr]; ok {
		if !r.IsAssigned(allowTemp) {
			return nil
		}

		if r.IncRef() {
			return r
		}

		s.releaseAddressState(r)
	}

	if !allowTemp && allowAnyInSubnet {
		for _, r := range s.endpoints {
			if r.GetKind() == PermanentExpired {
				continue
			}

			subnet := r.AddressWithPrefix().Subnet()
			if subnet.Contains(localAddr) {
				allowTemp = true
				break
			}
		}
	}

	if !allowTemp {
		return nil
	}

	r, _ := s.AddAddress(tcpip.AddressWithPrefix{
		Address:   localAddr,
		PrefixLen: len(localAddr) * 8,
	}, AddAddressOptions{
		Deprecated: false,
		ConfigType: AddressConfigStatic,
		Kind:       Temporary,
		PEB:        tempPEB,
	})
	return r
}

// PrimaryEndpoint implements AddressableEndpoint.
func (s *addressableEndpointState) PrimaryEndpoint(remoteAddr tcpip.Address, spoofingOrPromiscuous bool) AddressEndpoint {
	var deprecatedEndpoint *addressState
	for _, r := range s.primary {
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
					s.decAddressRef(deprecatedEndpoint)
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
func (s *addressableEndpointState) PrimaryAddresses() []tcpip.AddressWithPrefix {
	var addrs []tcpip.AddressWithPrefix
	for _, r := range s.primary {
		// Don't include tentative, expired or tempory endpoints
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

// AllAddresses implements AddressableEndpoint.
func (s *addressableEndpointState) AllAddresses() []tcpip.AddressWithPrefix {
	var addrs []tcpip.AddressWithPrefix
	for _, r := range s.endpoints {
		// Don't include tentative, expired or tempory endpoints
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

// RemoveAllAddresses implements AddressableEndpoint.
func (s *addressableEndpointState) RemoveAllAddresses() *tcpip.Error {
	var err *tcpip.Error
	for a, r := range s.endpoints {
		switch r.GetKind() {
		case PermanentTentative, Permanent:
			if tempErr := s.RemoveAddress(a); tempErr != nil && err == nil {
				err = tempErr
			}
		}
	}
	return err
}

var _ AddressEndpoint = (*addressState)(nil)

// addressState holds state for an address.
type addressState struct {
	networkState *addressableEndpointState
	addr         tcpip.AddressWithPrefix
	refs         int32

	kind       AddressKind
	configType AddressConfigType
	deprecated bool
}

// AddressWithPrefix implements AddressEndpoint.
func (s *addressState) AddressWithPrefix() tcpip.AddressWithPrefix {
	return s.addr
}

// GetKind implements AddressEndpoint.
func (s *addressState) GetKind() AddressKind {
	return AddressKind(atomic.LoadInt32((*int32)(&s.kind)))
}

// SetKind implements AddressEndpoint.
func (s *addressState) SetKind(kind AddressKind) {
	atomic.StoreInt32((*int32)(&s.kind), int32(kind))
}

// IsAssigned implements AddressEndpoint.
func (s *addressState) IsAssigned(spoofingOrPromiscuous bool) bool {
	switch s.GetKind() {
	case PermanentTentative:
		return false
	case PermanentExpired:
		return spoofingOrPromiscuous
	default:
		return true
	}
}

// IncRef implements AddressEndpoint.
func (s *addressState) IncRef() bool {
	for {
		v := atomic.LoadInt32(&s.refs)
		if v == 0 {
			return false
		}

		if atomic.CompareAndSwapInt32(&s.refs, v, v+1) {
			return true
		}
	}
}

// DecRef implements AddressEndpoint.
func (s *addressState) DecRef() bool {
	if s.decRef() {
		s.networkState.takeLockAndReleaseAddressState(s)
		return true
	}

	return false
}

func (s *addressState) decRef() bool {
	return atomic.AddInt32(&s.refs, -1) == 0
}

// ConfigType implements AddressEndpoint.
func (s *addressState) ConfigType() AddressConfigType {
	// Currently this is protected by the NIC lock.
	// TODO: protect this with the network endpoint lock once the NIC stops
	// writing to this.
	return s.configType
}

// SetDeprecated implements AddressEndpoint.
func (s *addressState) SetDeprecated(d bool) {
	// Currently this is protected by the NIC lock.
	// TODO: protect this with the network endpoint lock once the NIC stops
	// writing to this.
	s.deprecated = d
}

// Deprecated implements AddressEndpoint.
func (s *addressState) Deprecated() bool {
	// Currently this is protected by the NIC lock.
	// TODO: protect this with the network endpoint lock once the NIC stops
	// writing to this.
	return s.deprecated
}
