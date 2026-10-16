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

package sentryapi

import (
	"fmt"
	"net"
	"strings"

	"gvisor.dev/gvisor/pkg/urpc"
	"gvisor.dev/gvisor/runsc/config"
)

// DefaultLoopbackLink contains IP addresses and routes of "127.0.0.1/8" and
// "::1/8" on "lo" interface.
var DefaultLoopbackLink = LoopbackLink{
	Name: "lo",
	Addresses: []IPWithPrefix{
		{Address: net.IP("\x7f\x00\x00\x01"), PrefixLen: 8},
		{Address: net.IPv6loopback, PrefixLen: 128},
	},
	Routes: []Route{
		{
			Destination: net.IPNet{
				IP:   net.IPv4(0x7f, 0, 0, 0),
				Mask: net.IPv4Mask(0xff, 0, 0, 0),
			},
		},
		{
			Destination: net.IPNet{
				IP:   net.IPv6loopback,
				Mask: net.IPMask(strings.Repeat("\xff", net.IPv6len)),
			},
		},
	},
}

// Route represents a route in the network stack.
type Route struct {
	Destination net.IPNet
	Gateway     net.IP
	MTU         uint32
}

// DefaultRoute represents a catch all route to the default gateway.
type DefaultRoute struct {
	Route Route
	Name  string
}

// Neighbor represents an ARP/NDP neighbor entry to be added to the stack.
type Neighbor struct {
	IP           net.IP
	HardwareAddr net.HardwareAddr
}

// FDBasedLink configures an fd-based link.
type FDBasedLink struct {
	Name              string
	InterfaceIndex    int
	MTU               int
	Addresses         []IPWithPrefix
	Routes            []Route
	GSOMaxSize        uint32
	GVisorGSOEnabled  bool
	GVisorGRO         bool
	TXChecksumOffload bool
	RXChecksumOffload bool
	LinkAddress       net.HardwareAddr
	QDisc             config.QueueingDiscipline
	TBFRate           uint64
	TBFBurst          uint32
	Neighbors         []Neighbor

	// NumChannels controls how many underlying FDs are to be used to
	// create this endpoint.
	NumChannels int

	// ProcessorsPerChannel controls how many goroutines are used to handle
	// packets on each channel.
	ProcessorsPerChannel int

	// IsPacket indicates whether each FD in this link is a packet socket.
	IsPacket []bool

	// PreConfigured indicates that getsockname and setsockopt(PACKET_FANOUT)
	// have already been performed on the host FDs.
	PreConfigured bool

	// IsProxy indicates that this link is backed by a SOCK_SEQPACKET Unix domain
	// socket connected to an external network proxy rather than by AF_PACKET
	// sockets on a host device. Such a link carries bare IP packets with no
	// Ethernet header and has no L2 neighbor table.
	IsProxy bool
}

// BindOpt indicates whether the sentry or runsc process is responsible for
// binding the AF_XDP socket.
type BindOpt int

const (
	// BindSentry indicates the sentry process must call bind.
	BindSentry BindOpt = iota

	// BindRunsc indicates the runsc process must call bind.
	BindRunsc
)

// XDPLink configures an XDP link.
type XDPLink struct {
	Name              string
	InterfaceIndex    int
	MTU               int
	Addresses         []IPWithPrefix
	Routes            []Route
	TXChecksumOffload bool
	RXChecksumOffload bool
	LinkAddress       net.HardwareAddr
	QDisc             config.QueueingDiscipline
	TBFRate           uint64
	TBFBurst          uint32
	Neighbors         []Neighbor
	GVisorGRO         bool
	Bind              BindOpt

	// NumChannels controls how many underlying FDs are to be used to
	// create this endpoint.
	NumChannels int
}

// LoopbackLink configures a loopback link.
type LoopbackLink struct {
	Name      string
	Addresses []IPWithPrefix
	Routes    []Route
	GVisorGRO bool
}

// NetworkCreateLinksAndRoutes synchronously creates links and routes.
const NetworkCreateLinksAndRoutes = "Network.CreateLinksAndRoutes"

// CreateLinksAndRoutesArgs are arguments to CreateLinkAndRoutes.
type CreateLinksAndRoutesArgs struct {
	// FilePayload contains the fds associated with the FDBasedLinks. The
	// number of fd's should match the sum of the NumChannels field of the
	// FDBasedLink entries below.
	urpc.FilePayload

	LoopbackLinks []LoopbackLink
	FDBasedLinks  []FDBasedLink
	XDPLinks      []XDPLink

	Defaultv4Gateway DefaultRoute
	Defaultv6Gateway DefaultRoute

	// PCAP indicates that FilePayload also contains a PCAP log file.
	PCAP bool

	// LogPackets indicates that packets should be logged.
	LogPackets bool

	// NATBlob indicates whether FilePayload also contains an iptables NAT
	// ruleset.
	NATBlob bool

	// PauseExternalNetworking indicates whether external networking should be
	// disabled initially.
	PauseExternalNetworking bool

	// AllowConnectedOnSave indicates whether connections should be allowed to
	// remain connected during save.
	AllowConnectedOnSave bool

	// IsRestore indicates whether this is part of a restore flow.
	IsRestore bool
}

// NetworkInitPluginStack initializes third-party network stack.
const NetworkInitPluginStack = "Network.InitPluginStack"

// InitPluginStackArgs are arguments to InitPluginStack.
type InitPluginStackArgs struct {
	urpc.FilePayload

	InitStr string
}

// IPWithPrefix is an address with its subnet prefix length.
type IPWithPrefix struct {
	// Address is a network address.
	Address net.IP

	// PrefixLen is the subnet prefix length.
	PrefixLen int
}

func (ip IPWithPrefix) String() string {
	return fmt.Sprintf("%s/%d", ip.Address, ip.PrefixLen)
}

// Empty returns true if route hasn't been set.
func (r *Route) Empty() bool {
	return r.Destination.IP == nil && r.Destination.Mask == nil && r.Gateway == nil
}
