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

package epsocket

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/inet"
	"gvisor.dev/gvisor/pkg/sentry/socket/netfilter"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/iptables"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// Stack implements inet.Stack for netstack/tcpip/stack.Stack.
//
// +stateify savable
type Stack struct {
	Stack *stack.Stack `state:"manual"`
}

// SupportsIPv6 implements Stack.SupportsIPv6.
func (s *Stack) SupportsIPv6() bool {
	return s.Stack.CheckNetworkProtocol(ipv6.ProtocolNumber)
}

// Interfaces implements inet.Stack.Interfaces.
func (s *Stack) Interfaces() map[int32]inet.Interface {
	is := make(map[int32]inet.Interface)
	for id, ni := range s.Stack.NICInfo() {
		var devType uint16
		if ni.Flags.Loopback {
			devType = linux.ARPHRD_LOOPBACK
		}
		is[int32(id)] = inet.Interface{
			Name:       ni.Name,
			Addr:       []byte(ni.LinkAddress),
			Flags:      uint32(nicStateFlagsToLinux(ni.Flags)),
			DeviceType: devType,
			MTU:        ni.MTU,
		}
	}
	return is
}

// InterfaceAddrs implements inet.Stack.InterfaceAddrs.
func (s *Stack) InterfaceAddrs() map[int32][]inet.InterfaceAddr {
	nicAddrs := make(map[int32][]inet.InterfaceAddr)
	for id, ni := range s.Stack.NICInfo() {
		var addrs []inet.InterfaceAddr
		for _, a := range ni.ProtocolAddresses {
			var family uint8
			switch a.Protocol {
			case ipv4.ProtocolNumber:
				family = linux.AF_INET
			case ipv6.ProtocolNumber:
				family = linux.AF_INET6
			default:
				log.Warningf("Unknown network protocol in %+v", a)
				continue
			}

			addrs = append(addrs, inet.InterfaceAddr{
				Family:    family,
				PrefixLen: uint8(a.AddressWithPrefix.PrefixLen),
				Addr:      []byte(a.AddressWithPrefix.Address),
				// TODO(b/68878065): Other fields.
			})
		}
		nicAddrs[int32(id)] = addrs
	}
	return nicAddrs
}

// TCPReceiveBufferSize implements inet.Stack.TCPReceiveBufferSize.
func (s *Stack) TCPReceiveBufferSize() (inet.TCPBufferSize, error) {
	var rs tcp.ReceiveBufferSizeOption
	err := s.Stack.TransportProtocolOption(tcp.ProtocolNumber, &rs)
	return inet.TCPBufferSize{
		Min:     rs.Min,
		Default: rs.Default,
		Max:     rs.Max,
	}, syserr.TranslateNetstackError(err).ToError()
}

// SetTCPReceiveBufferSize implements inet.Stack.SetTCPReceiveBufferSize.
func (s *Stack) SetTCPReceiveBufferSize(size inet.TCPBufferSize) error {
	rs := tcp.ReceiveBufferSizeOption{
		Min:     size.Min,
		Default: size.Default,
		Max:     size.Max,
	}
	return syserr.TranslateNetstackError(s.Stack.SetTransportProtocolOption(tcp.ProtocolNumber, rs)).ToError()
}

// TCPSendBufferSize implements inet.Stack.TCPSendBufferSize.
func (s *Stack) TCPSendBufferSize() (inet.TCPBufferSize, error) {
	var ss tcp.SendBufferSizeOption
	err := s.Stack.TransportProtocolOption(tcp.ProtocolNumber, &ss)
	return inet.TCPBufferSize{
		Min:     ss.Min,
		Default: ss.Default,
		Max:     ss.Max,
	}, syserr.TranslateNetstackError(err).ToError()
}

// SetTCPSendBufferSize implements inet.Stack.SetTCPSendBufferSize.
func (s *Stack) SetTCPSendBufferSize(size inet.TCPBufferSize) error {
	ss := tcp.SendBufferSizeOption{
		Min:     size.Min,
		Default: size.Default,
		Max:     size.Max,
	}
	return syserr.TranslateNetstackError(s.Stack.SetTransportProtocolOption(tcp.ProtocolNumber, ss)).ToError()
}

// TCPSACKEnabled implements inet.Stack.TCPSACKEnabled.
func (s *Stack) TCPSACKEnabled() (bool, error) {
	var sack tcp.SACKEnabled
	err := s.Stack.TransportProtocolOption(tcp.ProtocolNumber, &sack)
	return bool(sack), syserr.TranslateNetstackError(err).ToError()
}

// SetTCPSACKEnabled implements inet.Stack.SetTCPSACKEnabled.
func (s *Stack) SetTCPSACKEnabled(enabled bool) error {
	return syserr.TranslateNetstackError(s.Stack.SetTransportProtocolOption(tcp.ProtocolNumber, tcp.SACKEnabled(enabled))).ToError()
}

// Statistics implements inet.Stack.Statistics.
func (s *Stack) Statistics(stat interface{}, arg string) error {
	return syserr.ErrEndpointOperation.ToError()
}

// RouteTable implements inet.Stack.RouteTable.
func (s *Stack) RouteTable() []inet.Route {
	var routeTable []inet.Route

	for _, rt := range s.Stack.GetRouteTable() {
		var family uint8
		switch len(rt.Destination) {
		case header.IPv4AddressSize:
			family = linux.AF_INET
		case header.IPv6AddressSize:
			family = linux.AF_INET6
		default:
			log.Warningf("Unknown network protocol in route %+v", rt)
			continue
		}

		dstSubnet, err := tcpip.NewSubnet(rt.Destination, rt.Mask)
		if err != nil {
			log.Warningf("Invalid destination & mask in route: %s(%s): %v", rt.Destination, rt.Mask, err)
			continue
		}
		routeTable = append(routeTable, inet.Route{
			Family: family,
			DstLen: uint8(dstSubnet.Prefix()), // The CIDR prefix for the destination.

			// Always return unspecified protocol since we have no notion of
			// protocol for routes.
			Protocol: linux.RTPROT_UNSPEC,
			// Set statically to LINK scope for now.
			//
			// TODO(gvisor.dev/issue/595): Set scope for routes.
			Scope: linux.RT_SCOPE_LINK,
			Type:  linux.RTN_UNICAST,

			DstAddr:         []byte(rt.Destination),
			OutputInterface: int32(rt.NIC),
			GatewayAddr:     []byte(rt.Gateway),
		})
	}

	return routeTable
}

// IPTables returns the stack's iptables.
func (s *Stack) IPTables() (iptables.IPTables, error) {
	return s.Stack.IPTables(), nil
}

// FillDefaultIPTables sets the stack's iptables to the default tables, which
// allow and do not modify all traffic.
func (s *Stack) FillDefaultIPTables() error {
	return netfilter.FillDefaultIPTables(s.Stack)
}
