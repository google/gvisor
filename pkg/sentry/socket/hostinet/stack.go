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

package hostinet

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"reflect"
	"strconv"
	"strings"
	"syscall"

	"gvisor.dev/gvisor/pkg/binary"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/inet"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
)

var defaultRecvBufSize = inet.TCPBufferSize{
	Min:     4096,
	Default: 87380,
	Max:     6291456,
}

var defaultSendBufSize = inet.TCPBufferSize{
	Min:     4096,
	Default: 16384,
	Max:     4194304,
}

// Stack implements inet.Stack for host sockets.
type Stack struct {
	// Stack is immutable.
	interfaces     map[int32]inet.Interface
	interfaceAddrs map[int32][]inet.InterfaceAddr
	routes         []inet.Route
	supportsIPv6   bool
	tcpRecvBufSize inet.TCPBufferSize
	tcpSendBufSize inet.TCPBufferSize
	tcpSACKEnabled bool
	netDevFile     *os.File
	netSNMPFile    *os.File
	ipv4Forwarding bool
	ipv6Forwarding bool
}

// NewStack returns an empty Stack containing no configuration.
func NewStack() *Stack {
	return &Stack{
		interfaces:     make(map[int32]inet.Interface),
		interfaceAddrs: make(map[int32][]inet.InterfaceAddr),
	}
}

// Configure sets up the stack using the current state of the host network.
func (s *Stack) Configure() error {
	if err := addHostInterfaces(s); err != nil {
		return err
	}

	if err := addHostRoutes(s); err != nil {
		return err
	}

	if _, err := os.Stat("/proc/net/if_inet6"); err == nil {
		s.supportsIPv6 = true
	}

	s.tcpRecvBufSize = defaultRecvBufSize
	if tcpRMem, err := readTCPBufferSizeFile("/proc/sys/net/ipv4/tcp_rmem"); err == nil {
		s.tcpRecvBufSize = tcpRMem
	} else {
		log.Warningf("Failed to read TCP receive buffer size, using default values")
	}

	s.tcpSendBufSize = defaultSendBufSize
	if tcpWMem, err := readTCPBufferSizeFile("/proc/sys/net/ipv4/tcp_wmem"); err == nil {
		s.tcpSendBufSize = tcpWMem
	} else {
		log.Warningf("Failed to read TCP send buffer size, using default values")
	}

	// SACK is important for performance and even compatibility, assume it's
	// enabled if we can't find the actual value.
	s.tcpSACKEnabled = true
	if sack, err := ioutil.ReadFile("/proc/sys/net/ipv4/tcp_sack"); err == nil {
		s.tcpSACKEnabled = strings.TrimSpace(string(sack)) != "0"
	} else {
		log.Warningf("Failed to read if TCP SACK if enabled, setting to true")
	}

	if f, err := os.Open("/proc/net/dev"); err != nil {
		log.Warningf("Failed to open /proc/net/dev: %v", err)
	} else {
		s.netDevFile = f
	}

	if f, err := os.Open("/proc/net/snmp"); err != nil {
		log.Warningf("Failed to open /proc/net/snmp: %v", err)
	} else {
		s.netSNMPFile = f
	}

	s.ipv4Forwarding = false
	if ipForwarding, err := ioutil.ReadFile("/proc/sys/net/ipv4/ip_forward"); err == nil {
		s.ipv4Forwarding = strings.TrimSpace(string(ipForwarding)) != "0"
	} else {
		log.Warningf("Failed to read if IPv4 forwarding is enabled, setting to false")
	}

	return nil
}

// ExtractHostInterfaces will populate an interface map and
// interfaceAddrs map with the results of the equivalent
// netlink messages.
func ExtractHostInterfaces(links []syscall.NetlinkMessage, addrs []syscall.NetlinkMessage, interfaces map[int32]inet.Interface, interfaceAddrs map[int32][]inet.InterfaceAddr) error {
	for _, link := range links {
		if link.Header.Type != syscall.RTM_NEWLINK {
			continue
		}
		if len(link.Data) < syscall.SizeofIfInfomsg {
			return fmt.Errorf("RTM_GETLINK returned RTM_NEWLINK message with invalid data length (%d bytes, expected at least %d bytes)", len(link.Data), syscall.SizeofIfInfomsg)
		}
		var ifinfo syscall.IfInfomsg
		binary.Unmarshal(link.Data[:syscall.SizeofIfInfomsg], usermem.ByteOrder, &ifinfo)
		inetIF := inet.Interface{
			DeviceType: ifinfo.Type,
			Flags:      ifinfo.Flags,
		}
		// Not clearly documented: syscall.ParseNetlinkRouteAttr will check the
		// syscall.NetlinkMessage.Header.Type and skip the struct ifinfomsg
		// accordingly.
		attrs, err := syscall.ParseNetlinkRouteAttr(&link)
		if err != nil {
			return fmt.Errorf("RTM_GETLINK returned RTM_NEWLINK message with invalid rtattrs: %v", err)
		}
		for _, attr := range attrs {
			switch attr.Attr.Type {
			case syscall.IFLA_ADDRESS:
				inetIF.Addr = attr.Value
			case syscall.IFLA_IFNAME:
				inetIF.Name = string(attr.Value[:len(attr.Value)-1])
			}
		}
		interfaces[ifinfo.Index] = inetIF
	}

	for _, addr := range addrs {
		if addr.Header.Type != syscall.RTM_NEWADDR {
			continue
		}
		if len(addr.Data) < syscall.SizeofIfAddrmsg {
			return fmt.Errorf("RTM_GETADDR returned RTM_NEWADDR message with invalid data length (%d bytes, expected at least %d bytes)", len(addr.Data), syscall.SizeofIfAddrmsg)
		}
		var ifaddr syscall.IfAddrmsg
		binary.Unmarshal(addr.Data[:syscall.SizeofIfAddrmsg], usermem.ByteOrder, &ifaddr)
		inetAddr := inet.InterfaceAddr{
			Family:    ifaddr.Family,
			PrefixLen: ifaddr.Prefixlen,
			Flags:     ifaddr.Flags,
		}
		attrs, err := syscall.ParseNetlinkRouteAttr(&addr)
		if err != nil {
			return fmt.Errorf("RTM_GETADDR returned RTM_NEWADDR message with invalid rtattrs: %v", err)
		}
		for _, attr := range attrs {
			switch attr.Attr.Type {
			case syscall.IFA_ADDRESS:
				inetAddr.Addr = attr.Value
			}
		}
		interfaceAddrs[int32(ifaddr.Index)] = append(interfaceAddrs[int32(ifaddr.Index)], inetAddr)
	}

	return nil
}

// ExtractHostRoutes populates the given routes slice with the data from the
// host route table.
func ExtractHostRoutes(routeMsgs []syscall.NetlinkMessage) ([]inet.Route, error) {
	var routes []inet.Route
	for _, routeMsg := range routeMsgs {
		if routeMsg.Header.Type != syscall.RTM_NEWROUTE {
			continue
		}

		var ifRoute syscall.RtMsg
		binary.Unmarshal(routeMsg.Data[:syscall.SizeofRtMsg], usermem.ByteOrder, &ifRoute)
		inetRoute := inet.Route{
			Family:   ifRoute.Family,
			DstLen:   ifRoute.Dst_len,
			SrcLen:   ifRoute.Src_len,
			TOS:      ifRoute.Tos,
			Table:    ifRoute.Table,
			Protocol: ifRoute.Protocol,
			Scope:    ifRoute.Scope,
			Type:     ifRoute.Type,
			Flags:    ifRoute.Flags,
		}

		// Not clearly documented: syscall.ParseNetlinkRouteAttr will check the
		// syscall.NetlinkMessage.Header.Type and skip the struct rtmsg
		// accordingly.
		attrs, err := syscall.ParseNetlinkRouteAttr(&routeMsg)
		if err != nil {
			return nil, fmt.Errorf("RTM_GETROUTE returned RTM_NEWROUTE message with invalid rtattrs: %v", err)
		}

		for _, attr := range attrs {
			switch attr.Attr.Type {
			case syscall.RTA_DST:
				inetRoute.DstAddr = attr.Value
			case syscall.RTA_SRC:
				inetRoute.SrcAddr = attr.Value
			case syscall.RTA_GATEWAY:
				inetRoute.GatewayAddr = attr.Value
			case syscall.RTA_OIF:
				expected := int(binary.Size(inetRoute.OutputInterface))
				if len(attr.Value) != expected {
					return nil, fmt.Errorf("RTM_GETROUTE returned RTM_NEWROUTE message with invalid attribute data length (%d bytes, expected %d bytes)", len(attr.Value), expected)
				}
				binary.Unmarshal(attr.Value, usermem.ByteOrder, &inetRoute.OutputInterface)
			}
		}

		routes = append(routes, inetRoute)
	}

	return routes, nil
}

func addHostInterfaces(s *Stack) error {
	links, err := doNetlinkRouteRequest(syscall.RTM_GETLINK)
	if err != nil {
		return fmt.Errorf("RTM_GETLINK failed: %v", err)
	}

	addrs, err := doNetlinkRouteRequest(syscall.RTM_GETADDR)
	if err != nil {
		return fmt.Errorf("RTM_GETADDR failed: %v", err)
	}

	return ExtractHostInterfaces(links, addrs, s.interfaces, s.interfaceAddrs)
}

func addHostRoutes(s *Stack) error {
	routes, err := doNetlinkRouteRequest(syscall.RTM_GETROUTE)
	if err != nil {
		return fmt.Errorf("RTM_GETROUTE failed: %v", err)
	}

	s.routes, err = ExtractHostRoutes(routes)
	if err != nil {
		return err
	}

	return nil
}

func doNetlinkRouteRequest(req int) ([]syscall.NetlinkMessage, error) {
	data, err := syscall.NetlinkRIB(req, syscall.AF_UNSPEC)
	if err != nil {
		return nil, err
	}
	return syscall.ParseNetlinkMessage(data)
}

func readTCPBufferSizeFile(filename string) (inet.TCPBufferSize, error) {
	contents, err := ioutil.ReadFile(filename)
	if err != nil {
		return inet.TCPBufferSize{}, fmt.Errorf("failed to read %s: %v", filename, err)
	}
	ioseq := usermem.BytesIOSequence(contents)
	fields := make([]int32, 3)
	if n, err := usermem.CopyInt32StringsInVec(context.Background(), ioseq.IO, ioseq.Addrs, fields, ioseq.Opts); n != ioseq.NumBytes() || err != nil {
		return inet.TCPBufferSize{}, fmt.Errorf("failed to parse %s (%q): got %v after %d/%d bytes", filename, contents, err, n, ioseq.NumBytes())
	}
	return inet.TCPBufferSize{
		Min:     int(fields[0]),
		Default: int(fields[1]),
		Max:     int(fields[2]),
	}, nil
}

// Interfaces implements inet.Stack.Interfaces.
func (s *Stack) Interfaces() map[int32]inet.Interface {
	interfaces := make(map[int32]inet.Interface)
	for k, v := range s.interfaces {
		interfaces[k] = v
	}
	return interfaces
}

// InterfaceAddrs implements inet.Stack.InterfaceAddrs.
func (s *Stack) InterfaceAddrs() map[int32][]inet.InterfaceAddr {
	addrs := make(map[int32][]inet.InterfaceAddr)
	for k, v := range s.interfaceAddrs {
		addrs[k] = append([]inet.InterfaceAddr(nil), v...)
	}
	return addrs
}

// SupportsIPv6 implements inet.Stack.SupportsIPv6.
func (s *Stack) SupportsIPv6() bool {
	return s.supportsIPv6
}

// TCPReceiveBufferSize implements inet.Stack.TCPReceiveBufferSize.
func (s *Stack) TCPReceiveBufferSize() (inet.TCPBufferSize, error) {
	return s.tcpRecvBufSize, nil
}

// SetTCPReceiveBufferSize implements inet.Stack.SetTCPReceiveBufferSize.
func (s *Stack) SetTCPReceiveBufferSize(size inet.TCPBufferSize) error {
	return syserror.EACCES
}

// TCPSendBufferSize implements inet.Stack.TCPSendBufferSize.
func (s *Stack) TCPSendBufferSize() (inet.TCPBufferSize, error) {
	return s.tcpSendBufSize, nil
}

// SetTCPSendBufferSize implements inet.Stack.SetTCPSendBufferSize.
func (s *Stack) SetTCPSendBufferSize(size inet.TCPBufferSize) error {
	return syserror.EACCES
}

// TCPSACKEnabled implements inet.Stack.TCPSACKEnabled.
func (s *Stack) TCPSACKEnabled() (bool, error) {
	return s.tcpSACKEnabled, nil
}

// SetTCPSACKEnabled implements inet.Stack.SetTCPSACKEnabled.
func (s *Stack) SetTCPSACKEnabled(enabled bool) error {
	return syserror.EACCES
}

// getLine reads one line from proc file, with specified prefix.
// The last argument, withHeader, specifies if it contains line header.
func getLine(f *os.File, prefix string, withHeader bool) string {
	data := make([]byte, 4096)

	if _, err := f.Seek(0, 0); err != nil {
		return ""
	}

	if _, err := io.ReadFull(f, data); err != io.ErrUnexpectedEOF {
		return ""
	}

	prefix = prefix + ":"
	lines := strings.Split(string(data), "\n")
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, prefix) {
			if withHeader {
				withHeader = false
				continue
			}
			return l
		}
	}
	return ""
}

func toSlice(i interface{}) []uint64 {
	v := reflect.Indirect(reflect.ValueOf(i))
	return v.Slice(0, v.Len()).Interface().([]uint64)
}

// Statistics implements inet.Stack.Statistics.
func (s *Stack) Statistics(stat interface{}, arg string) error {
	var (
		snmpTCP   bool
		rawLine   string
		sliceStat []uint64
	)

	switch stat.(type) {
	case *inet.StatDev:
		if s.netDevFile == nil {
			return fmt.Errorf("/proc/net/dev is not opened for hostinet")
		}
		rawLine = getLine(s.netDevFile, arg, false /* with no header */)
	case *inet.StatSNMPIP, *inet.StatSNMPICMP, *inet.StatSNMPICMPMSG, *inet.StatSNMPTCP, *inet.StatSNMPUDP, *inet.StatSNMPUDPLite:
		if s.netSNMPFile == nil {
			return fmt.Errorf("/proc/net/snmp is not opened for hostinet")
		}
		rawLine = getLine(s.netSNMPFile, arg, true)
	default:
		return syserr.ErrEndpointOperation.ToError()
	}

	if rawLine == "" {
		return fmt.Errorf("Failed to get raw line")
	}

	parts := strings.SplitN(rawLine, ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("Failed to get prefix from: %q", rawLine)
	}

	sliceStat = toSlice(stat)
	fields := strings.Fields(strings.TrimSpace(parts[1]))
	if len(fields) != len(sliceStat) {
		return fmt.Errorf("Failed to parse fields: %q", rawLine)
	}
	if _, ok := stat.(*inet.StatSNMPTCP); ok {
		snmpTCP = true
	}
	for i := 0; i < len(sliceStat); i++ {
		var err error
		if snmpTCP && i == 3 {
			var tmp int64
			// MaxConn field is signed, RFC 2012.
			tmp, err = strconv.ParseInt(fields[i], 10, 64)
			sliceStat[i] = uint64(tmp) // Convert back to int before use.
		} else {
			sliceStat[i], err = strconv.ParseUint(fields[i], 10, 64)
		}
		if err != nil {
			return fmt.Errorf("Failed to parse field %d from: %q, %v", i, rawLine, err)
		}
	}

	return nil
}

// RouteTable implements inet.Stack.RouteTable.
func (s *Stack) RouteTable() []inet.Route {
	return append([]inet.Route(nil), s.routes...)
}

// Resume implements inet.Stack.Resume.
func (s *Stack) Resume() {}

// Forwarding implements inet.Stack.Forwarding.
func (s *Stack) Forwarding(protocol tcpip.NetworkProtocolNumber) bool {
	switch protocol {
	case ipv4.ProtocolNumber:
		return s.ipv4Forwarding
	case ipv6.ProtocolNumber:
		return s.ipv6Forwarding
	default:
		log.Warningf("Forwarding(%v) failed: unsupported protocol", protocol)
		return false
	}
}

// SetForwarding implements inet.Stack.SetForwarding.
func (s *Stack) SetForwarding(protocol tcpip.NetworkProtocolNumber, enable bool) error {
	return syserror.EACCES
}
