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

package netstack

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/inet"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
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

// Converts Netstack's ARPHardwareType to equivalent linux constants.
func toLinuxARPHardwareType(t header.ARPHardwareType) uint16 {
	switch t {
	case header.ARPHardwareNone:
		return linux.ARPHRD_NONE
	case header.ARPHardwareLoopback:
		return linux.ARPHRD_LOOPBACK
	case header.ARPHardwareEther:
		return linux.ARPHRD_ETHER
	default:
		panic(fmt.Sprintf("unknown ARPHRD type: %d", t))
	}
}

// Interfaces implements inet.Stack.Interfaces.
func (s *Stack) Interfaces() map[int32]inet.Interface {
	is := make(map[int32]inet.Interface)
	for id, ni := range s.Stack.NICInfo() {
		is[int32(id)] = inet.Interface{
			Name:       ni.Name,
			Addr:       []byte(ni.LinkAddress),
			Flags:      uint32(nicStateFlagsToLinux(ni.Flags)),
			DeviceType: toLinuxARPHardwareType(ni.ARPHardwareType),
			MTU:        ni.MTU,
		}
	}
	return is
}

// RemoveInterface implements inet.Stack.RemoveInterface.
func (s *Stack) RemoveInterface(idx int32) error {
	nic := tcpip.NICID(idx)
	return syserr.TranslateNetstackError(s.Stack.RemoveNIC(nic)).ToError()
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

// convertAddr converts an InterfaceAddr to a ProtocolAddress.
func convertAddr(addr inet.InterfaceAddr) (tcpip.ProtocolAddress, error) {
	var (
		protocol        tcpip.NetworkProtocolNumber
		address         tcpip.Address
		protocolAddress tcpip.ProtocolAddress
	)
	switch addr.Family {
	case linux.AF_INET:
		if len(addr.Addr) != header.IPv4AddressSize {
			return protocolAddress, linuxerr.EINVAL
		}
		if addr.PrefixLen > header.IPv4AddressSize*8 {
			return protocolAddress, linuxerr.EINVAL
		}
		protocol = ipv4.ProtocolNumber
		address = tcpip.Address(addr.Addr)
	case linux.AF_INET6:
		if len(addr.Addr) != header.IPv6AddressSize {
			return protocolAddress, linuxerr.EINVAL
		}
		if addr.PrefixLen > header.IPv6AddressSize*8 {
			return protocolAddress, linuxerr.EINVAL
		}
		protocol = ipv6.ProtocolNumber
		address = tcpip.Address(addr.Addr)
	default:
		return protocolAddress, linuxerr.ENOTSUP
	}

	protocolAddress = tcpip.ProtocolAddress{
		Protocol: protocol,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   address,
			PrefixLen: int(addr.PrefixLen),
		},
	}
	return protocolAddress, nil
}

// AddInterfaceAddr implements inet.Stack.AddInterfaceAddr.
func (s *Stack) AddInterfaceAddr(idx int32, addr inet.InterfaceAddr) error {
	protocolAddress, err := convertAddr(addr)
	if err != nil {
		return err
	}

	// Attach address to interface.
	nicID := tcpip.NICID(idx)
	if err := s.Stack.AddProtocolAddress(nicID, protocolAddress, stack.AddressProperties{}); err != nil {
		return syserr.TranslateNetstackError(err).ToError()
	}

	// Add route for local network if it doesn't exist already.
	localRoute := tcpip.Route{
		Destination: protocolAddress.AddressWithPrefix.Subnet(),
		Gateway:     "", // No gateway for local network.
		NIC:         nicID,
	}

	for _, rt := range s.Stack.GetRouteTable() {
		if rt.Equal(localRoute) {
			return nil
		}
	}

	// Local route does not exist yet. Add it.
	s.Stack.AddRoute(localRoute)

	return nil
}

// RemoveInterfaceAddr implements inet.Stack.RemoveInterfaceAddr.
func (s *Stack) RemoveInterfaceAddr(idx int32, addr inet.InterfaceAddr) error {
	protocolAddress, err := convertAddr(addr)
	if err != nil {
		return err
	}

	// Remove addresses matching the address and prefix.
	nicID := tcpip.NICID(idx)
	if err := s.Stack.RemoveAddress(nicID, protocolAddress.AddressWithPrefix.Address); err != nil {
		return syserr.TranslateNetstackError(err).ToError()
	}

	// Remove the corresponding local network route if it exists.
	localRoute := tcpip.Route{
		Destination: protocolAddress.AddressWithPrefix.Subnet(),
		Gateway:     "", // No gateway for local network.
		NIC:         nicID,
	}
	s.Stack.RemoveRoutes(func(rt tcpip.Route) bool {
		return rt.Equal(localRoute)
	})

	return nil
}

// TCPReceiveBufferSize implements inet.Stack.TCPReceiveBufferSize.
func (s *Stack) TCPReceiveBufferSize() (inet.TCPBufferSize, error) {
	var rs tcpip.TCPReceiveBufferSizeRangeOption
	err := s.Stack.TransportProtocolOption(tcp.ProtocolNumber, &rs)
	return inet.TCPBufferSize{
		Min:     rs.Min,
		Default: rs.Default,
		Max:     rs.Max,
	}, syserr.TranslateNetstackError(err).ToError()
}

// SetTCPReceiveBufferSize implements inet.Stack.SetTCPReceiveBufferSize.
func (s *Stack) SetTCPReceiveBufferSize(size inet.TCPBufferSize) error {
	rs := tcpip.TCPReceiveBufferSizeRangeOption{
		Min:     size.Min,
		Default: size.Default,
		Max:     size.Max,
	}
	return syserr.TranslateNetstackError(s.Stack.SetTransportProtocolOption(tcp.ProtocolNumber, &rs)).ToError()
}

// TCPSendBufferSize implements inet.Stack.TCPSendBufferSize.
func (s *Stack) TCPSendBufferSize() (inet.TCPBufferSize, error) {
	var ss tcpip.TCPSendBufferSizeRangeOption
	err := s.Stack.TransportProtocolOption(tcp.ProtocolNumber, &ss)
	return inet.TCPBufferSize{
		Min:     ss.Min,
		Default: ss.Default,
		Max:     ss.Max,
	}, syserr.TranslateNetstackError(err).ToError()
}

// SetTCPSendBufferSize implements inet.Stack.SetTCPSendBufferSize.
func (s *Stack) SetTCPSendBufferSize(size inet.TCPBufferSize) error {
	ss := tcpip.TCPSendBufferSizeRangeOption{
		Min:     size.Min,
		Default: size.Default,
		Max:     size.Max,
	}
	return syserr.TranslateNetstackError(s.Stack.SetTransportProtocolOption(tcp.ProtocolNumber, &ss)).ToError()
}

// TCPSACKEnabled implements inet.Stack.TCPSACKEnabled.
func (s *Stack) TCPSACKEnabled() (bool, error) {
	var sack tcpip.TCPSACKEnabled
	err := s.Stack.TransportProtocolOption(tcp.ProtocolNumber, &sack)
	return bool(sack), syserr.TranslateNetstackError(err).ToError()
}

// SetTCPSACKEnabled implements inet.Stack.SetTCPSACKEnabled.
func (s *Stack) SetTCPSACKEnabled(enabled bool) error {
	opt := tcpip.TCPSACKEnabled(enabled)
	return syserr.TranslateNetstackError(s.Stack.SetTransportProtocolOption(tcp.ProtocolNumber, &opt)).ToError()
}

// TCPRecovery implements inet.Stack.TCPRecovery.
func (s *Stack) TCPRecovery() (inet.TCPLossRecovery, error) {
	var recovery tcpip.TCPRecovery
	if err := s.Stack.TransportProtocolOption(tcp.ProtocolNumber, &recovery); err != nil {
		return 0, syserr.TranslateNetstackError(err).ToError()
	}
	return inet.TCPLossRecovery(recovery), nil
}

// SetTCPRecovery implements inet.Stack.SetTCPRecovery.
func (s *Stack) SetTCPRecovery(recovery inet.TCPLossRecovery) error {
	opt := tcpip.TCPRecovery(recovery)
	return syserr.TranslateNetstackError(s.Stack.SetTransportProtocolOption(tcp.ProtocolNumber, &opt)).ToError()
}

// Statistics implements inet.Stack.Statistics.
func (s *Stack) Statistics(stat interface{}, arg string) error {
	switch stats := stat.(type) {
	case *inet.StatDev:
		for _, ni := range s.Stack.NICInfo() {
			if ni.Name != arg {
				continue
			}
			// TODO(gvisor.dev/issue/2103) Support stubbed stats.
			*stats = inet.StatDev{
				// Receive section.
				ni.Stats.Rx.Bytes.Value(),   // bytes.
				ni.Stats.Rx.Packets.Value(), // packets.
				0,                           // errs.
				0,                           // drop.
				0,                           // fifo.
				0,                           // frame.
				0,                           // compressed.
				0,                           // multicast.
				// Transmit section.
				ni.Stats.Tx.Bytes.Value(),   // bytes.
				ni.Stats.Tx.Packets.Value(), // packets.
				0,                           // errs.
				0,                           // drop.
				0,                           // fifo.
				0,                           // colls.
				0,                           // carrier.
				0,                           // compressed.
			}
			break
		}
	case *inet.StatSNMPIP:
		ip := Metrics.IP
		// TODO(gvisor.dev/issue/969) Support stubbed stats.
		*stats = inet.StatSNMPIP{
			0,                          // Ip/Forwarding.
			0,                          // Ip/DefaultTTL.
			ip.PacketsReceived.Value(), // InReceives.
			0,                          // Ip/InHdrErrors.
			ip.InvalidDestinationAddressesReceived.Value(), // InAddrErrors.
			0,                               // Ip/ForwDatagrams.
			0,                               // Ip/InUnknownProtos.
			0,                               // Ip/InDiscards.
			ip.PacketsDelivered.Value(),     // InDelivers.
			ip.PacketsSent.Value(),          // OutRequests.
			ip.OutgoingPacketErrors.Value(), // OutDiscards.
			0,                               // Ip/OutNoRoutes.
			0,                               // Support Ip/ReasmTimeout.
			0,                               // Support Ip/ReasmReqds.
			0,                               // Support Ip/ReasmOKs.
			0,                               // Support Ip/ReasmFails.
			0,                               // Support Ip/FragOKs.
			0,                               // Support Ip/FragFails.
			0,                               // Support Ip/FragCreates.
		}
	case *inet.StatSNMPICMP:
		in := Metrics.ICMP.V4.PacketsReceived.ICMPv4PacketStats
		out := Metrics.ICMP.V4.PacketsSent.ICMPv4PacketStats
		// TODO(gvisor.dev/issue/969) Support stubbed stats.
		*stats = inet.StatSNMPICMP{
			0, // Icmp/InMsgs.
			Metrics.ICMP.V4.PacketsSent.Dropped.Value(), // InErrors.
			0,                         // Icmp/InCsumErrors.
			in.DstUnreachable.Value(), // InDestUnreachs.
			in.TimeExceeded.Value(),   // InTimeExcds.
			in.ParamProblem.Value(),   // InParmProbs.
			in.SrcQuench.Value(),      // InSrcQuenchs.
			in.Redirect.Value(),       // InRedirects.
			in.EchoRequest.Value(),    // InEchos.
			in.EchoReply.Value(),      // InEchoReps.
			in.Timestamp.Value(),      // InTimestamps.
			in.TimestampReply.Value(), // InTimestampReps.
			in.InfoRequest.Value(),    // InAddrMasks.
			in.InfoReply.Value(),      // InAddrMaskReps.
			0,                         // Icmp/OutMsgs.
			Metrics.ICMP.V4.PacketsReceived.Invalid.Value(), // OutErrors.
			out.DstUnreachable.Value(),                      // OutDestUnreachs.
			out.TimeExceeded.Value(),                        // OutTimeExcds.
			out.ParamProblem.Value(),                        // OutParmProbs.
			out.SrcQuench.Value(),                           // OutSrcQuenchs.
			out.Redirect.Value(),                            // OutRedirects.
			out.EchoRequest.Value(),                         // OutEchos.
			out.EchoReply.Value(),                           // OutEchoReps.
			out.Timestamp.Value(),                           // OutTimestamps.
			out.TimestampReply.Value(),                      // OutTimestampReps.
			out.InfoRequest.Value(),                         // OutAddrMasks.
			out.InfoReply.Value(),                           // OutAddrMaskReps.
		}
	case *inet.StatSNMPTCP:
		tcp := Metrics.TCP
		// RFC 2012 (updates 1213):  SNMPv2-MIB-TCP.
		*stats = inet.StatSNMPTCP{
			1,                                     // RtoAlgorithm.
			200,                                   // RtoMin.
			120000,                                // RtoMax.
			(1<<64 - 1),                           // MaxConn.
			tcp.ActiveConnectionOpenings.Value(),  // ActiveOpens.
			tcp.PassiveConnectionOpenings.Value(), // PassiveOpens.
			tcp.FailedConnectionAttempts.Value(),  // AttemptFails.
			tcp.EstablishedResets.Value(),         // EstabResets.
			tcp.CurrentEstablished.Value(),        // CurrEstab.
			tcp.ValidSegmentsReceived.Value(),     // InSegs.
			tcp.SegmentsSent.Value(),              // OutSegs.
			tcp.Retransmits.Value(),               // RetransSegs.
			tcp.InvalidSegmentsReceived.Value(),   // InErrs.
			tcp.ResetsSent.Value(),                // OutRsts.
			tcp.ChecksumErrors.Value(),            // InCsumErrors.
		}
	case *inet.StatSNMPUDP:
		udp := Metrics.UDP
		// TODO(gvisor.dev/issue/969) Support stubbed stats.
		*stats = inet.StatSNMPUDP{
			udp.PacketsReceived.Value(),     // InDatagrams.
			udp.UnknownPortErrors.Value(),   // NoPorts.
			0,                               // Udp/InErrors.
			udp.PacketsSent.Value(),         // OutDatagrams.
			udp.ReceiveBufferErrors.Value(), // RcvbufErrors.
			0,                               // Udp/SndbufErrors.
			udp.ChecksumErrors.Value(),      // Udp/InCsumErrors.
			0,                               // Udp/IgnoredMulti.
		}
	default:
		return syserr.ErrEndpointOperation.ToError()
	}
	return nil
}

// RouteTable implements inet.Stack.RouteTable.
func (s *Stack) RouteTable() []inet.Route {
	var routeTable []inet.Route

	for _, rt := range s.Stack.GetRouteTable() {
		var family uint8
		switch len(rt.Destination.ID()) {
		case header.IPv4AddressSize:
			family = linux.AF_INET
		case header.IPv6AddressSize:
			family = linux.AF_INET6
		default:
			log.Warningf("Unknown network protocol in route %+v", rt)
			continue
		}

		routeTable = append(routeTable, inet.Route{
			Family: family,
			DstLen: uint8(rt.Destination.Prefix()), // The CIDR prefix for the destination.

			// Always return unspecified protocol since we have no notion of
			// protocol for routes.
			Protocol: linux.RTPROT_UNSPEC,
			// Set statically to LINK scope for now.
			//
			// TODO(gvisor.dev/issue/595): Set scope for routes.
			Scope: linux.RT_SCOPE_LINK,
			Type:  linux.RTN_UNICAST,

			DstAddr:         []byte(rt.Destination.ID()),
			OutputInterface: int32(rt.NIC),
			GatewayAddr:     []byte(rt.Gateway),
		})
	}

	return routeTable
}

// IPTables returns the stack's iptables.
func (s *Stack) IPTables() (*stack.IPTables, error) {
	return s.Stack.IPTables(), nil
}

// Resume implements inet.Stack.Resume.
func (s *Stack) Resume() {
	s.Stack.Resume()
}

// RegisteredEndpoints implements inet.Stack.RegisteredEndpoints.
func (s *Stack) RegisteredEndpoints() []stack.TransportEndpoint {
	return s.Stack.RegisteredEndpoints()
}

// CleanupEndpoints implements inet.Stack.CleanupEndpoints.
func (s *Stack) CleanupEndpoints() []stack.TransportEndpoint {
	return s.Stack.CleanupEndpoints()
}

// RestoreCleanupEndpoints implements inet.Stack.RestoreCleanupEndpoints.
func (s *Stack) RestoreCleanupEndpoints(es []stack.TransportEndpoint) {
	s.Stack.RestoreCleanupEndpoints(es)
}

// SetForwarding implements inet.Stack.SetForwarding.
func (s *Stack) SetForwarding(protocol tcpip.NetworkProtocolNumber, enable bool) error {
	if err := s.Stack.SetForwardingDefaultAndAllNICs(protocol, enable); err != nil {
		return fmt.Errorf("SetForwardingDefaultAndAllNICs(%d, %t): %s", protocol, enable, err)
	}
	return nil
}

// PortRange implements inet.Stack.PortRange.
func (s *Stack) PortRange() (uint16, uint16) {
	return s.Stack.PortRange()
}

// SetPortRange implements inet.Stack.SetPortRange.
func (s *Stack) SetPortRange(start uint16, end uint16) error {
	return syserr.TranslateNetstackError(s.Stack.SetPortRange(start, end)).ToError()
}
