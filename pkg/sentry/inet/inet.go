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

// Package inet defines semantics for IP stacks.
package inet

import (
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Stack represents a TCP/IP stack.
type Stack interface {
	// Interfaces returns all network interfaces as a mapping from interface
	// indexes to interface properties. Interface indices are strictly positive
	// integers.
	Interfaces() map[int32]Interface

	// InterfaceAddrs returns all network interface addresses as a mapping from
	// interface indexes to a slice of associated interface address properties.
	InterfaceAddrs() map[int32][]InterfaceAddr

	// AddInterfaceAddr adds an address to the network interface identified by
	// idx.
	AddInterfaceAddr(idx int32, addr InterfaceAddr) error

	// RemoveInterfaceAddr removes an address from the network interface
	// identified by idx.
	RemoveInterfaceAddr(idx int32, addr InterfaceAddr) error

	// SupportsIPv6 returns true if the stack supports IPv6 connectivity.
	SupportsIPv6() bool

	// TCPReceiveBufferSize returns TCP receive buffer size settings.
	TCPReceiveBufferSize() (TCPBufferSize, error)

	// SetTCPReceiveBufferSize attempts to change TCP receive buffer size
	// settings.
	SetTCPReceiveBufferSize(size TCPBufferSize) error

	// TCPSendBufferSize returns TCP send buffer size settings.
	TCPSendBufferSize() (TCPBufferSize, error)

	// SetTCPSendBufferSize attempts to change TCP send buffer size settings.
	SetTCPSendBufferSize(size TCPBufferSize) error

	// TCPSACKEnabled returns true if RFC 2018 TCP Selective Acknowledgements
	// are enabled.
	TCPSACKEnabled() (bool, error)

	// SetTCPSACKEnabled attempts to change TCP selective acknowledgement
	// settings.
	SetTCPSACKEnabled(enabled bool) error

	// TCPRecovery returns the TCP loss detection algorithm.
	TCPRecovery() (TCPLossRecovery, error)

	// SetTCPRecovery attempts to change TCP loss detection algorithm.
	SetTCPRecovery(recovery TCPLossRecovery) error

	// Statistics reports stack statistics.
	Statistics(stat interface{}, arg string) error

	// RouteTable returns the network stack's route table.
	RouteTable() []Route

	// Resume restarts the network stack after restore.
	Resume()

	// RegisteredEndpoints returns all endpoints which are currently registered.
	RegisteredEndpoints() []stack.TransportEndpoint

	// CleanupEndpoints returns endpoints currently in the cleanup state.
	CleanupEndpoints() []stack.TransportEndpoint

	// RestoreCleanupEndpoints adds endpoints to cleanup tracking. This is useful
	// for restoring a stack after a save.
	RestoreCleanupEndpoints([]stack.TransportEndpoint)

	// Forwarding returns if packet forwarding between NICs is enabled.
	Forwarding(protocol tcpip.NetworkProtocolNumber) bool

	// SetForwarding enables or disables packet forwarding between NICs.
	SetForwarding(protocol tcpip.NetworkProtocolNumber, enable bool) error
}

// Interface contains information about a network interface.
type Interface struct {
	// DeviceType is the device type, a Linux ARPHRD_* constant.
	DeviceType uint16

	// Flags is the device flags; see netdevice(7), under "Ioctls",
	// "SIOCGIFFLAGS, SIOCSIFFLAGS".
	Flags uint32

	// Name is the device name.
	Name string

	// Addr is the hardware device address.
	Addr []byte

	// MTU is the maximum transmission unit.
	MTU uint32
}

// InterfaceAddr contains information about a network interface address.
type InterfaceAddr struct {
	// Family is the address family, a Linux AF_* constant.
	Family uint8

	// PrefixLen is the address prefix length.
	PrefixLen uint8

	// Flags is the address flags.
	Flags uint8

	// Addr is the actual address.
	Addr []byte
}

// TCPBufferSize contains settings controlling TCP buffer sizing.
//
// +stateify savable
type TCPBufferSize struct {
	// Min is the minimum size.
	Min int

	// Default is the default size.
	Default int

	// Max is the maximum size.
	Max int
}

// StatDev describes one line of /proc/net/dev, i.e., stats for one network
// interface.
type StatDev [16]uint64

// Route contains information about a network route.
type Route struct {
	// Family is the address family, a Linux AF_* constant.
	Family uint8

	// DstLen is the length of the destination address.
	DstLen uint8

	// SrcLen is the length of the source address.
	SrcLen uint8

	// TOS is the Type of Service filter.
	TOS uint8

	// Table is the routing table ID.
	Table uint8

	// Protocol is the route origin, a Linux RTPROT_* constant.
	Protocol uint8

	// Scope is the distance to destination, a Linux RT_SCOPE_* constant.
	Scope uint8

	// Type is the route origin, a Linux RTN_* constant.
	Type uint8

	// Flags are route flags. See rtnetlink(7) under "rtm_flags".
	Flags uint32

	// DstAddr is the route destination address (RTA_DST).
	DstAddr []byte

	// SrcAddr is the route source address (RTA_SRC).
	SrcAddr []byte

	// OutputInterface is the output interface index (RTA_OIF).
	OutputInterface int32

	// GatewayAddr is the route gateway address (RTA_GATEWAY).
	GatewayAddr []byte
}

// Below SNMP metrics are from Linux/usr/include/linux/snmp.h.

// StatSNMPIP describes Ip line of /proc/net/snmp.
type StatSNMPIP [19]uint64

// StatSNMPICMP describes Icmp line of /proc/net/snmp.
type StatSNMPICMP [27]uint64

// StatSNMPICMPMSG describes IcmpMsg line of /proc/net/snmp.
type StatSNMPICMPMSG [512]uint64

// StatSNMPTCP describes Tcp line of /proc/net/snmp.
type StatSNMPTCP [15]uint64

// StatSNMPUDP describes Udp line of /proc/net/snmp.
type StatSNMPUDP [8]uint64

// StatSNMPUDPLite describes UdpLite line of /proc/net/snmp.
type StatSNMPUDPLite [8]uint64

// TCPLossRecovery indicates TCP loss detection and recovery methods to use.
type TCPLossRecovery int32

// Loss recovery constants from include/net/tcp.h which are used to set
// /proc/sys/net/ipv4/tcp_recovery.
const (
	TCP_RACK_LOSS_DETECTION TCPLossRecovery = 1 << iota
	TCP_RACK_STATIC_REO_WND
	TCP_RACK_NO_DUPTHRESH
)
