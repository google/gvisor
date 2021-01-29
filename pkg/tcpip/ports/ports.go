// Copyright 2018 The gVisor Authors.
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

// Package ports provides PortManager that manages allocating, reserving and releasing ports.
package ports

import (
	"math"
	"math/rand"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
)

const (
	// FirstEphemeral is the first ephemeral port.
	FirstEphemeral = 16000

	// numEphemeralPorts it the mnumber of available ephemeral ports to
	// Netstack.
	numEphemeralPorts = math.MaxUint16 - FirstEphemeral + 1

	anyIPAddress tcpip.Address = ""
)

type portDescriptor struct {
	network   tcpip.NetworkProtocolNumber
	transport tcpip.TransportProtocolNumber
	port      uint16
}

// Flags represents the type of port reservation.
//
// +stateify savable
type Flags struct {
	// MostRecent represents UDP SO_REUSEADDR.
	MostRecent bool

	// LoadBalanced indicates SO_REUSEPORT.
	//
	// LoadBalanced takes precidence over MostRecent.
	LoadBalanced bool

	// TupleOnly represents TCP SO_REUSEADDR.
	TupleOnly bool
}

// Bits converts the Flags to their bitset form.
func (f Flags) Bits() BitFlags {
	var rf BitFlags
	if f.MostRecent {
		rf |= MostRecentFlag
	}
	if f.LoadBalanced {
		rf |= LoadBalancedFlag
	}
	if f.TupleOnly {
		rf |= TupleOnlyFlag
	}
	return rf
}

// Effective returns the effective behavior of a flag config.
func (f Flags) Effective() Flags {
	e := f
	if e.LoadBalanced && e.MostRecent {
		e.MostRecent = false
	}
	return e
}

// PortManager manages allocating, reserving and releasing ports.
type PortManager struct {
	mu             sync.RWMutex
	allocatedPorts map[portDescriptor]bindAddresses

	// hint is used to pick ports ephemeral ports in a stable order for
	// a given port offset.
	//
	// hint must be accessed using the portHint/incPortHint helpers.
	// TODO(gvisor.dev/issue/940): S/R this field.
	hint uint32
}

// BitFlags is a bitset representation of Flags.
type BitFlags uint32

const (
	// MostRecentFlag represents Flags.MostRecent.
	MostRecentFlag BitFlags = 1 << iota

	// LoadBalancedFlag represents Flags.LoadBalanced.
	LoadBalancedFlag

	// TupleOnlyFlag represents Flags.TupleOnly.
	TupleOnlyFlag

	// nextFlag is the value that the next added flag will have.
	//
	// It is used to calculate FlagMask below. It is also the number of
	// valid flag states.
	nextFlag

	// FlagMask is a bit mask for BitFlags.
	FlagMask = nextFlag - 1

	// MultiBindFlagMask contains the flags that allow binding the same
	// tuple multiple times.
	MultiBindFlagMask = MostRecentFlag | LoadBalancedFlag
)

// ToFlags converts the bitset into a Flags struct.
func (f BitFlags) ToFlags() Flags {
	return Flags{
		MostRecent:   f&MostRecentFlag != 0,
		LoadBalanced: f&LoadBalancedFlag != 0,
		TupleOnly:    f&TupleOnlyFlag != 0,
	}
}

// FlagCounter counts how many references each flag combination has.
type FlagCounter struct {
	// refs stores the count for each possible flag combination, (0 though
	// FlagMask).
	refs [nextFlag]int
}

// AddRef increases the reference count for a specific flag combination.
func (c *FlagCounter) AddRef(flags BitFlags) {
	c.refs[flags]++
}

// DropRef decreases the reference count for a specific flag combination.
func (c *FlagCounter) DropRef(flags BitFlags) {
	c.refs[flags]--
}

// TotalRefs calculates the total number of references for all flag
// combinations.
func (c FlagCounter) TotalRefs() int {
	var total int
	for _, r := range c.refs {
		total += r
	}
	return total
}

// FlagRefs returns the number of references with all specified flags.
func (c FlagCounter) FlagRefs(flags BitFlags) int {
	var total int
	for i, r := range c.refs {
		if BitFlags(i)&flags == flags {
			total += r
		}
	}
	return total
}

// AllRefsHave returns if all references have all specified flags.
func (c FlagCounter) AllRefsHave(flags BitFlags) bool {
	for i, r := range c.refs {
		if BitFlags(i)&flags != flags && r > 0 {
			return false
		}
	}
	return true
}

// IntersectionRefs returns the set of flags shared by all references.
func (c FlagCounter) IntersectionRefs() BitFlags {
	intersection := FlagMask
	for i, r := range c.refs {
		if r > 0 {
			intersection &= BitFlags(i)
		}
	}
	return intersection
}

type destination struct {
	addr tcpip.Address
	port uint16
}

func makeDestination(a tcpip.FullAddress) destination {
	return destination{
		a.Addr,
		a.Port,
	}
}

// portNode is never empty. When it has no elements, it is removed from the
// map that references it.
type portNode map[destination]FlagCounter

// intersectionRefs calculates the intersection of flag bit values which affect
// the specified destination.
//
// If no destinations are present, all flag values are returned as there are no
// entries to limit possible flag values of a new entry.
//
// In addition to the intersection, the number of intersecting refs is
// returned.
func (p portNode) intersectionRefs(dst destination) (BitFlags, int) {
	intersection := FlagMask
	var count int

	for d, f := range p {
		if d == dst {
			intersection &= f.IntersectionRefs()
			count++
			continue
		}
		// Wildcard destinations affect all destinations for TupleOnly.
		if d.addr == anyIPAddress || dst.addr == anyIPAddress {
			// Only bitwise and the TupleOnlyFlag.
			intersection &= ((^TupleOnlyFlag) | f.IntersectionRefs())
			count++
		}
	}

	return intersection, count
}

// deviceNode is never empty. When it has no elements, it is removed from the
// map that references it.
type deviceNode map[tcpip.NICID]portNode

// isAvailable checks whether binding is possible by device. If not binding to a
// device, check against all FlagCounters. If binding to a specific device, check
// against the unspecified device and the provided device.
//
// If either of the port reuse flags is enabled on any of the nodes, all nodes
// sharing a port must share at least one reuse flag. This matches Linux's
// behavior.
func (d deviceNode) isAvailable(flags Flags, bindToDevice tcpip.NICID, dst destination) bool {
	flagBits := flags.Bits()
	if bindToDevice == 0 {
		intersection := FlagMask
		for _, p := range d {
			i, c := p.intersectionRefs(dst)
			if c == 0 {
				continue
			}
			intersection &= i
			if intersection&flagBits == 0 {
				// Can't bind because the (addr,port) was
				// previously bound without reuse.
				return false
			}
		}
		return true
	}

	intersection := FlagMask

	if p, ok := d[0]; ok {
		var c int
		intersection, c = p.intersectionRefs(dst)
		if c > 0 && intersection&flagBits == 0 {
			return false
		}
	}

	if p, ok := d[bindToDevice]; ok {
		i, c := p.intersectionRefs(dst)
		intersection &= i
		if c > 0 && intersection&flagBits == 0 {
			return false
		}
	}

	return true
}

// bindAddresses is a set of IP addresses.
type bindAddresses map[tcpip.Address]deviceNode

// isAvailable checks whether an IP address is available to bind to. If the
// address is the "any" address, check all other addresses. Otherwise, just
// check against the "any" address and the provided address.
func (b bindAddresses) isAvailable(addr tcpip.Address, flags Flags, bindToDevice tcpip.NICID, dst destination) bool {
	if addr == anyIPAddress {
		// If binding to the "any" address then check that there are no conflicts
		// with all addresses.
		for _, d := range b {
			if !d.isAvailable(flags, bindToDevice, dst) {
				return false
			}
		}
		return true
	}

	// Check that there is no conflict with the "any" address.
	if d, ok := b[anyIPAddress]; ok {
		if !d.isAvailable(flags, bindToDevice, dst) {
			return false
		}
	}

	// Check that this is no conflict with the provided address.
	if d, ok := b[addr]; ok {
		if !d.isAvailable(flags, bindToDevice, dst) {
			return false
		}
	}

	return true
}

// NewPortManager creates new PortManager.
func NewPortManager() *PortManager {
	return &PortManager{allocatedPorts: make(map[portDescriptor]bindAddresses)}
}

// PickEphemeralPort randomly chooses a starting point and iterates over all
// possible ephemeral ports, allowing the caller to decide whether a given port
// is suitable for its needs, and stopping when a port is found or an error
// occurs.
func (s *PortManager) PickEphemeralPort(testPort func(p uint16) (bool, tcpip.Error)) (port uint16, err tcpip.Error) {
	offset := uint32(rand.Int31n(numEphemeralPorts))
	return s.pickEphemeralPort(offset, numEphemeralPorts, testPort)
}

// portHint atomically reads and returns the s.hint value.
func (s *PortManager) portHint() uint32 {
	return atomic.LoadUint32(&s.hint)
}

// incPortHint atomically increments s.hint by 1.
func (s *PortManager) incPortHint() {
	atomic.AddUint32(&s.hint, 1)
}

// PickEphemeralPortStable starts at the specified offset + s.portHint and
// iterates over all ephemeral ports, allowing the caller to decide whether a
// given port is suitable for its needs and stopping when a port is found or an
// error occurs.
func (s *PortManager) PickEphemeralPortStable(offset uint32, testPort func(p uint16) (bool, tcpip.Error)) (port uint16, err tcpip.Error) {
	p, err := s.pickEphemeralPort(s.portHint()+offset, numEphemeralPorts, testPort)
	if err == nil {
		s.incPortHint()
	}
	return p, err

}

// pickEphemeralPort starts at the offset specified from the FirstEphemeral port
// and iterates over the number of ports specified by count and allows the
// caller to decide whether a given port is suitable for its needs, and stopping
// when a port is found or an error occurs.
func (s *PortManager) pickEphemeralPort(offset, count uint32, testPort func(p uint16) (bool, tcpip.Error)) (port uint16, err tcpip.Error) {
	for i := uint32(0); i < count; i++ {
		port = uint16(FirstEphemeral + (offset+i)%count)
		ok, err := testPort(port)
		if err != nil {
			return 0, err
		}

		if ok {
			return port, nil
		}
	}

	return 0, &tcpip.ErrNoPortAvailable{}
}

// IsPortAvailable tests if the given port is available on all given protocols.
func (s *PortManager) IsPortAvailable(networks []tcpip.NetworkProtocolNumber, transport tcpip.TransportProtocolNumber, addr tcpip.Address, port uint16, flags Flags, bindToDevice tcpip.NICID, dest tcpip.FullAddress) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.isPortAvailableLocked(networks, transport, addr, port, flags, bindToDevice, makeDestination(dest))
}

func (s *PortManager) isPortAvailableLocked(networks []tcpip.NetworkProtocolNumber, transport tcpip.TransportProtocolNumber, addr tcpip.Address, port uint16, flags Flags, bindToDevice tcpip.NICID, dst destination) bool {
	for _, network := range networks {
		desc := portDescriptor{network, transport, port}
		if addrs, ok := s.allocatedPorts[desc]; ok {
			if !addrs.isAvailable(addr, flags, bindToDevice, dst) {
				return false
			}
		}
	}
	return true
}

// ReservePort marks a port/IP combination as reserved so that it cannot be
// reserved by another endpoint. If port is zero, ReservePort will search for
// an unreserved ephemeral port and reserve it, returning its value in the
// "port" return value.
//
// An optional testPort closure can be passed in which if provided will be used
// to test if the picked port can be used. The function should return true if
// the port is safe to use, false otherwise.
func (s *PortManager) ReservePort(networks []tcpip.NetworkProtocolNumber, transport tcpip.TransportProtocolNumber, addr tcpip.Address, port uint16, flags Flags, bindToDevice tcpip.NICID, dest tcpip.FullAddress, testPort func(port uint16) bool) (reservedPort uint16, err tcpip.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	dst := makeDestination(dest)

	// If a port is specified, just try to reserve it for all network
	// protocols.
	if port != 0 {
		if !s.reserveSpecificPort(networks, transport, addr, port, flags, bindToDevice, dst) {
			return 0, &tcpip.ErrPortInUse{}
		}
		if testPort != nil && !testPort(port) {
			s.releasePortLocked(networks, transport, addr, port, flags.Bits(), bindToDevice, dst)
			return 0, &tcpip.ErrPortInUse{}
		}
		return port, nil
	}

	// A port wasn't specified, so try to find one.
	return s.PickEphemeralPort(func(p uint16) (bool, tcpip.Error) {
		if !s.reserveSpecificPort(networks, transport, addr, p, flags, bindToDevice, dst) {
			return false, nil
		}
		if testPort != nil && !testPort(p) {
			s.releasePortLocked(networks, transport, addr, p, flags.Bits(), bindToDevice, dst)
			return false, nil
		}
		return true, nil
	})
}

// reserveSpecificPort tries to reserve the given port on all given protocols.
func (s *PortManager) reserveSpecificPort(networks []tcpip.NetworkProtocolNumber, transport tcpip.TransportProtocolNumber, addr tcpip.Address, port uint16, flags Flags, bindToDevice tcpip.NICID, dst destination) bool {
	if !s.isPortAvailableLocked(networks, transport, addr, port, flags, bindToDevice, dst) {
		return false
	}

	flagBits := flags.Bits()

	// Reserve port on all network protocols.
	for _, network := range networks {
		desc := portDescriptor{network, transport, port}
		m, ok := s.allocatedPorts[desc]
		if !ok {
			m = make(bindAddresses)
			s.allocatedPorts[desc] = m
		}
		d, ok := m[addr]
		if !ok {
			d = make(deviceNode)
			m[addr] = d
		}
		p := d[bindToDevice]
		if p == nil {
			p = make(portNode)
		}
		n := p[dst]
		n.AddRef(flagBits)
		p[dst] = n
		d[bindToDevice] = p
	}

	return true
}

// ReserveTuple adds a port reservation for the tuple on all given protocol.
func (s *PortManager) ReserveTuple(networks []tcpip.NetworkProtocolNumber, transport tcpip.TransportProtocolNumber, addr tcpip.Address, port uint16, flags Flags, bindToDevice tcpip.NICID, dest tcpip.FullAddress) bool {
	flagBits := flags.Bits()
	dst := makeDestination(dest)

	s.mu.Lock()
	defer s.mu.Unlock()

	// It is easier to undo the entire reservation, so if we find that the
	// tuple can't be fully added, finish and undo the whole thing.
	undo := false

	// Reserve port on all network protocols.
	for _, network := range networks {
		desc := portDescriptor{network, transport, port}
		m, ok := s.allocatedPorts[desc]
		if !ok {
			m = make(bindAddresses)
			s.allocatedPorts[desc] = m
		}
		d, ok := m[addr]
		if !ok {
			d = make(deviceNode)
			m[addr] = d
		}
		p := d[bindToDevice]
		if p == nil {
			p = make(portNode)
		}

		n := p[dst]
		if n.TotalRefs() != 0 && n.IntersectionRefs()&flagBits == 0 {
			// Tuple already exists.
			undo = true
		}
		n.AddRef(flagBits)
		p[dst] = n
		d[bindToDevice] = p
	}

	if undo {
		// releasePortLocked decrements the counts (rather than setting
		// them to zero), so it will undo the incorrect incrementing
		// above.
		s.releasePortLocked(networks, transport, addr, port, flagBits, bindToDevice, dst)
		return false
	}

	return true
}

// ReleasePort releases the reservation on a port/IP combination so that it can
// be reserved by other endpoints.
func (s *PortManager) ReleasePort(networks []tcpip.NetworkProtocolNumber, transport tcpip.TransportProtocolNumber, addr tcpip.Address, port uint16, flags Flags, bindToDevice tcpip.NICID, dest tcpip.FullAddress) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.releasePortLocked(networks, transport, addr, port, flags.Bits(), bindToDevice, makeDestination(dest))
}

func (s *PortManager) releasePortLocked(networks []tcpip.NetworkProtocolNumber, transport tcpip.TransportProtocolNumber, addr tcpip.Address, port uint16, flags BitFlags, bindToDevice tcpip.NICID, dst destination) {
	for _, network := range networks {
		desc := portDescriptor{network, transport, port}
		if m, ok := s.allocatedPorts[desc]; ok {
			d, ok := m[addr]
			if !ok {
				continue
			}
			p, ok := d[bindToDevice]
			if !ok {
				continue
			}
			n, ok := p[dst]
			if !ok {
				continue
			}
			n.DropRef(flags)
			if n.TotalRefs() > 0 {
				p[dst] = n
				continue
			}
			delete(p, dst)
			if len(p) > 0 {
				continue
			}
			delete(d, bindToDevice)
			if len(d) > 0 {
				continue
			}
			delete(m, addr)
			if len(m) > 0 {
				continue
			}
			delete(s.allocatedPorts, desc)
		}
	}
}
