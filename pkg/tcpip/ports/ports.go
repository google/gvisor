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
	"sync"
	"sync/atomic"

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
}

func (f Flags) bits() reuseFlag {
	var rf reuseFlag
	if f.MostRecent {
		rf |= mostRecentFlag
	}
	if f.LoadBalanced {
		rf |= loadBalancedFlag
	}
	return rf
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

type reuseFlag int

const (
	mostRecentFlag reuseFlag = 1 << iota
	loadBalancedFlag
	nextFlag

	flagMask = nextFlag - 1
)

type portNode struct {
	// refs stores the count for each possible flag combination.
	refs [nextFlag]int
}

func (p portNode) totalRefs() int {
	var total int
	for _, r := range p.refs {
		total += r
	}
	return total
}

// flagRefs returns the number of references with all specified flags.
func (p portNode) flagRefs(flags reuseFlag) int {
	var total int
	for i, r := range p.refs {
		if reuseFlag(i)&flags == flags {
			total += r
		}
	}
	return total
}

// allRefsHave returns if all references have all specified flags.
func (p portNode) allRefsHave(flags reuseFlag) bool {
	for i, r := range p.refs {
		if reuseFlag(i)&flags == flags && r > 0 {
			return false
		}
	}
	return true
}

// intersectionRefs returns the set of flags shared by all references.
func (p portNode) intersectionRefs() reuseFlag {
	intersection := flagMask
	for i, r := range p.refs {
		if r > 0 {
			intersection &= reuseFlag(i)
		}
	}
	return intersection
}

// deviceNode is never empty. When it has no elements, it is removed from the
// map that references it.
type deviceNode map[tcpip.NICID]portNode

// isAvailable checks whether binding is possible by device. If not binding to a
// device, check against all portNodes. If binding to a specific device, check
// against the unspecified device and the provided device.
//
// If either of the port reuse flags is enabled on any of the nodes, all nodes
// sharing a port must share at least one reuse flag. This matches Linux's
// behavior.
func (d deviceNode) isAvailable(flags Flags, bindToDevice tcpip.NICID) bool {
	flagBits := flags.bits()
	if bindToDevice == 0 {
		// Trying to binding all devices.
		if flagBits == 0 {
			// Can't bind because the (addr,port) is already bound.
			return false
		}
		intersection := flagMask
		for _, p := range d {
			i := p.intersectionRefs()
			intersection &= i
			if intersection&flagBits == 0 {
				// Can't bind because the (addr,port) was
				// previously bound without reuse.
				return false
			}
		}
		return true
	}

	intersection := flagMask

	if p, ok := d[0]; ok {
		intersection = p.intersectionRefs()
		if intersection&flagBits == 0 {
			return false
		}
	}

	if p, ok := d[bindToDevice]; ok {
		i := p.intersectionRefs()
		intersection &= i
		if intersection&flagBits == 0 {
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
func (b bindAddresses) isAvailable(addr tcpip.Address, flags Flags, bindToDevice tcpip.NICID) bool {
	if addr == anyIPAddress {
		// If binding to the "any" address then check that there are no conflicts
		// with all addresses.
		for _, d := range b {
			if !d.isAvailable(flags, bindToDevice) {
				return false
			}
		}
		return true
	}

	// Check that there is no conflict with the "any" address.
	if d, ok := b[anyIPAddress]; ok {
		if !d.isAvailable(flags, bindToDevice) {
			return false
		}
	}

	// Check that this is no conflict with the provided address.
	if d, ok := b[addr]; ok {
		if !d.isAvailable(flags, bindToDevice) {
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
func (s *PortManager) PickEphemeralPort(testPort func(p uint16) (bool, *tcpip.Error)) (port uint16, err *tcpip.Error) {
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
func (s *PortManager) PickEphemeralPortStable(offset uint32, testPort func(p uint16) (bool, *tcpip.Error)) (port uint16, err *tcpip.Error) {
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
func (s *PortManager) pickEphemeralPort(offset, count uint32, testPort func(p uint16) (bool, *tcpip.Error)) (port uint16, err *tcpip.Error) {
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

	return 0, tcpip.ErrNoPortAvailable
}

// IsPortAvailable tests if the given port is available on all given protocols.
func (s *PortManager) IsPortAvailable(networks []tcpip.NetworkProtocolNumber, transport tcpip.TransportProtocolNumber, addr tcpip.Address, port uint16, flags Flags, bindToDevice tcpip.NICID) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.isPortAvailableLocked(networks, transport, addr, port, flags, bindToDevice)
}

func (s *PortManager) isPortAvailableLocked(networks []tcpip.NetworkProtocolNumber, transport tcpip.TransportProtocolNumber, addr tcpip.Address, port uint16, flags Flags, bindToDevice tcpip.NICID) bool {
	for _, network := range networks {
		desc := portDescriptor{network, transport, port}
		if addrs, ok := s.allocatedPorts[desc]; ok {
			if !addrs.isAvailable(addr, flags, bindToDevice) {
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
func (s *PortManager) ReservePort(networks []tcpip.NetworkProtocolNumber, transport tcpip.TransportProtocolNumber, addr tcpip.Address, port uint16, flags Flags, bindToDevice tcpip.NICID) (reservedPort uint16, err *tcpip.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// If a port is specified, just try to reserve it for all network
	// protocols.
	if port != 0 {
		if !s.reserveSpecificPort(networks, transport, addr, port, flags, bindToDevice) {
			return 0, tcpip.ErrPortInUse
		}
		return port, nil
	}

	// A port wasn't specified, so try to find one.
	return s.PickEphemeralPort(func(p uint16) (bool, *tcpip.Error) {
		return s.reserveSpecificPort(networks, transport, addr, p, flags, bindToDevice), nil
	})
}

// reserveSpecificPort tries to reserve the given port on all given protocols.
func (s *PortManager) reserveSpecificPort(networks []tcpip.NetworkProtocolNumber, transport tcpip.TransportProtocolNumber, addr tcpip.Address, port uint16, flags Flags, bindToDevice tcpip.NICID) bool {
	if !s.isPortAvailableLocked(networks, transport, addr, port, flags, bindToDevice) {
		return false
	}
	flagBits := flags.bits()

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
		n := d[bindToDevice]
		n.refs[flagBits]++
		d[bindToDevice] = n
	}

	return true
}

// ReleasePort releases the reservation on a port/IP combination so that it can
// be reserved by other endpoints.
func (s *PortManager) ReleasePort(networks []tcpip.NetworkProtocolNumber, transport tcpip.TransportProtocolNumber, addr tcpip.Address, port uint16, flags Flags, bindToDevice tcpip.NICID) {
	s.mu.Lock()
	defer s.mu.Unlock()

	flagBits := flags.bits()

	for _, network := range networks {
		desc := portDescriptor{network, transport, port}
		if m, ok := s.allocatedPorts[desc]; ok {
			d, ok := m[addr]
			if !ok {
				continue
			}
			n, ok := d[bindToDevice]
			if !ok {
				continue
			}
			n.refs[flagBits]--
			d[bindToDevice] = n
			if n.refs == [nextFlag]int{} {
				delete(d, bindToDevice)
			}
			if len(d) == 0 {
				delete(m, addr)
			}
			if len(m) == 0 {
				delete(s.allocatedPorts, desc)
			}
		}
	}
}
