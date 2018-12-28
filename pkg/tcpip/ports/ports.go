// Copyright 2018 Google LLC
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

	"gvisor.googlesource.com/gvisor/pkg/tcpip"
)

const (
	// FirstEphemeral is the first ephemeral port.
	FirstEphemeral = 16000

	anyIPAddress tcpip.Address = ""
)

type portDescriptor struct {
	network   tcpip.NetworkProtocolNumber
	transport tcpip.TransportProtocolNumber
	port      uint16
}

// PortManager manages allocating, reserving and releasing ports.
type PortManager struct {
	mu             sync.RWMutex
	allocatedPorts map[portDescriptor]bindAddresses
}

type portNode struct {
	reuse bool
	refs  int
}

// bindAddresses is a set of IP addresses.
type bindAddresses map[tcpip.Address]portNode

// isAvailable checks whether an IP address is available to bind to.
func (b bindAddresses) isAvailable(addr tcpip.Address, reuse bool) bool {
	if addr == anyIPAddress {
		if len(b) == 0 {
			return true
		}
		if !reuse {
			return false
		}
		for _, n := range b {
			if !n.reuse {
				return false
			}
		}
		return true
	}

	// If all addresses for this portDescriptor are already bound, no
	// address is available.
	if n, ok := b[anyIPAddress]; ok {
		if !reuse {
			return false
		}
		if !n.reuse {
			return false
		}
	}

	if n, ok := b[addr]; ok {
		if !reuse {
			return false
		}
		return n.reuse
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
	count := uint16(math.MaxUint16 - FirstEphemeral + 1)
	offset := uint16(rand.Int31n(int32(count)))

	for i := uint16(0); i < count; i++ {
		port = FirstEphemeral + (offset+i)%count
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
func (s *PortManager) IsPortAvailable(networks []tcpip.NetworkProtocolNumber, transport tcpip.TransportProtocolNumber, addr tcpip.Address, port uint16, reuse bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.isPortAvailableLocked(networks, transport, addr, port, reuse)
}

func (s *PortManager) isPortAvailableLocked(networks []tcpip.NetworkProtocolNumber, transport tcpip.TransportProtocolNumber, addr tcpip.Address, port uint16, reuse bool) bool {
	for _, network := range networks {
		desc := portDescriptor{network, transport, port}
		if addrs, ok := s.allocatedPorts[desc]; ok {
			if !addrs.isAvailable(addr, reuse) {
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
func (s *PortManager) ReservePort(networks []tcpip.NetworkProtocolNumber, transport tcpip.TransportProtocolNumber, addr tcpip.Address, port uint16, reuse bool) (reservedPort uint16, err *tcpip.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// If a port is specified, just try to reserve it for all network
	// protocols.
	if port != 0 {
		if !s.reserveSpecificPort(networks, transport, addr, port, reuse) {
			return 0, tcpip.ErrPortInUse
		}
		return port, nil
	}

	// A port wasn't specified, so try to find one.
	return s.PickEphemeralPort(func(p uint16) (bool, *tcpip.Error) {
		return s.reserveSpecificPort(networks, transport, addr, p, reuse), nil
	})
}

// reserveSpecificPort tries to reserve the given port on all given protocols.
func (s *PortManager) reserveSpecificPort(networks []tcpip.NetworkProtocolNumber, transport tcpip.TransportProtocolNumber, addr tcpip.Address, port uint16, reuse bool) bool {
	if !s.isPortAvailableLocked(networks, transport, addr, port, reuse) {
		return false
	}

	// Reserve port on all network protocols.
	for _, network := range networks {
		desc := portDescriptor{network, transport, port}
		m, ok := s.allocatedPorts[desc]
		if !ok {
			m = make(bindAddresses)
			s.allocatedPorts[desc] = m
		}
		if n, ok := m[addr]; ok {
			n.refs++
			m[addr] = n
		} else {
			m[addr] = portNode{reuse: reuse, refs: 1}
		}
	}

	return true
}

// ReleasePort releases the reservation on a port/IP combination so that it can
// be reserved by other endpoints.
func (s *PortManager) ReleasePort(networks []tcpip.NetworkProtocolNumber, transport tcpip.TransportProtocolNumber, addr tcpip.Address, port uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, network := range networks {
		desc := portDescriptor{network, transport, port}
		if m, ok := s.allocatedPorts[desc]; ok {
			n, ok := m[addr]
			if !ok {
				continue
			}
			n.refs--
			if n.refs == 0 {
				delete(m, addr)
			} else {
				m[addr] = n
			}
			if len(m) == 0 {
				delete(s.allocatedPorts, desc)
			}
		}
	}
}
