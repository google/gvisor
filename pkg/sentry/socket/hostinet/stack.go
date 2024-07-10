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

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/inet"
	"gvisor.dev/gvisor/pkg/sentry/socket/netlink/nlmsg"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/usermem"
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
	supportsIPv6   bool
	tcpRecovery    inet.TCPLossRecovery
	tcpRecvBufSize inet.TCPBufferSize
	tcpSendBufSize inet.TCPBufferSize
	tcpSACKEnabled bool
	netDevFile     *os.File
	netSNMPFile    *os.File
	// allowedSocketTypes is the list of allowed socket types
	allowedSocketTypes []AllowedSocketType
}

// Destroy implements inet.Stack.Destroy.
func (*Stack) Destroy() {
}

// NewStack returns an empty Stack containing no configuration.
func NewStack() *Stack {
	return &Stack{}
}

// Configure sets up the stack using the current state of the host network.
func (s *Stack) Configure(allowRawSockets bool) error {
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

	s.allowedSocketTypes = AllowedSocketTypes
	if allowRawSockets {
		s.allowedSocketTypes = append(s.allowedSocketTypes, AllowedRawSocketTypes...)
	}

	return nil
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
	ifs, err := getInterfaces()
	if err != nil {
		log.Warningf("could not get host interface: %v", err)
		return nil
	}

	// query interface features for each of the host interfaces.
	if err := queryInterfaceFeatures(ifs); err != nil {
		log.Warningf("could not query host interfaces: %v", err)
		return nil
	}
	return ifs
}

// RemoveInterface implements inet.Stack.RemoveInterface.
func (*Stack) RemoveInterface(idx int32) error {
	return removeInterface(idx)
}

// InterfaceAddrs implements inet.Stack.InterfaceAddrs.
func (s *Stack) InterfaceAddrs() map[int32][]inet.InterfaceAddr {
	addrs, err := getInterfaceAddrs()
	if err != nil {
		log.Warningf("failed to get host interface addresses: %v", err)
		return nil
	}
	return addrs
}

// SetInterface implements inet.Stack.SetInterface.
func (s *Stack) SetInterface(ctx context.Context, msg *nlmsg.Message) *syserr.Error {
	var ifinfomsg linux.InterfaceInfoMessage
	attrs, ok := msg.GetData(&ifinfomsg)
	if !ok {
		return syserr.ErrInvalidArgument
	}
	for !attrs.Empty() {
		// The index is unspecified, search by the interface name.
		ahdr, value, rest, ok := attrs.ParseFirst()
		if !ok {
			return syserr.ErrInvalidArgument
		}
		attrs = rest
		switch ahdr.Type {
		case linux.IFLA_IFNAME:
			if len(value) < 1 {
				return syserr.ErrInvalidArgument
			}
			if ifinfomsg.Index != 0 {
				// Device name changing isn't supported yet.
				return syserr.ErrNotSupported
			}
			ifname := string(value[:len(value)-1])
			for idx, ifa := range s.Interfaces() {
				if ifname == ifa.Name {
					ifinfomsg.Index = idx
					break
				}
			}
		default:
			ctx.Warningf("unexpected attribute: %x", ahdr.Type)
			return syserr.ErrNotSupported
		}
	}
	if ifinfomsg.Index == 0 {
		return syserr.ErrNoDevice
	}

	flags := msg.Header().Flags
	if flags&(linux.NLM_F_EXCL|linux.NLM_F_REPLACE) != 0 {
		return syserr.ErrExists
	}

	if ifinfomsg.Flags != 0 || ifinfomsg.Change != 0 {
		if ifinfomsg.Change & ^uint32(linux.IFF_UP) != 0 {
			ctx.Warningf("Unsupported ifi_change flags: %x", ifinfomsg.Change)
			return syserr.ErrInvalidArgument
		}
		if ifinfomsg.Flags & ^uint32(linux.IFF_UP) != 0 {
			ctx.Warningf("Unsupported ifi_flags: %x", ifinfomsg.Change)
			return syserr.ErrInvalidArgument
		}
		// Netstack interfaces are always up.
	}
	return nil
}

// AddInterfaceAddr implements inet.Stack.AddInterfaceAddr.
func (*Stack) AddInterfaceAddr(idx int32, addr inet.InterfaceAddr) error {
	return addInterfaceAddr(idx, addr)
}

// RemoveInterfaceAddr implements inet.Stack.RemoveInterfaceAddr.
func (*Stack) RemoveInterfaceAddr(idx int32, addr inet.InterfaceAddr) error {
	return removeInterfaceAddr(idx, addr)
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
func (*Stack) SetTCPReceiveBufferSize(inet.TCPBufferSize) error {
	return linuxerr.EACCES
}

// TCPSendBufferSize implements inet.Stack.TCPSendBufferSize.
func (s *Stack) TCPSendBufferSize() (inet.TCPBufferSize, error) {
	return s.tcpSendBufSize, nil
}

// SetTCPSendBufferSize implements inet.Stack.SetTCPSendBufferSize.
func (*Stack) SetTCPSendBufferSize(inet.TCPBufferSize) error {
	return linuxerr.EACCES
}

// TCPSACKEnabled implements inet.Stack.TCPSACKEnabled.
func (s *Stack) TCPSACKEnabled() (bool, error) {
	return s.tcpSACKEnabled, nil
}

// SetTCPSACKEnabled implements inet.Stack.SetTCPSACKEnabled.
func (*Stack) SetTCPSACKEnabled(bool) error {
	return linuxerr.EACCES
}

// TCPRecovery implements inet.Stack.TCPRecovery.
func (s *Stack) TCPRecovery() (inet.TCPLossRecovery, error) {
	return s.tcpRecovery, nil
}

// SetTCPRecovery implements inet.Stack.SetTCPRecovery.
func (*Stack) SetTCPRecovery(inet.TCPLossRecovery) error {
	return linuxerr.EACCES
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

func toSlice(i any) []uint64 {
	v := reflect.Indirect(reflect.ValueOf(i))
	return v.Slice(0, v.Len()).Interface().([]uint64)
}

// Statistics implements inet.Stack.Statistics.
func (s *Stack) Statistics(stat any, arg string) error {
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
		return fmt.Errorf("failed to get raw line")
	}

	parts := strings.SplitN(rawLine, ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("failed to get prefix from: %q", rawLine)
	}

	sliceStat = toSlice(stat)
	fields := strings.Fields(strings.TrimSpace(parts[1]))
	if len(fields) != len(sliceStat) {
		return fmt.Errorf("failed to parse fields: %q", rawLine)
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
			return fmt.Errorf("failed to parse field %d from: %q, %v", i, rawLine, err)
		}
	}

	return nil
}

// RouteTable implements inet.Stack.RouteTable.
func (s *Stack) RouteTable() []inet.Route {
	routes, err := getRoutes()
	if err != nil {
		log.Warningf("failed to get routes: %v", err)
		return nil
	}
	// Prepend empty route.
	return append([]inet.Route(nil), routes...)
}

// NewRoute implements inet.Stack.NewRoute.
func (*Stack) NewRoute(context.Context, *nlmsg.Message) *syserr.Error {
	// TODO(b/343524351): implements RTM_NEWROUTE for hostinet.
	return syserr.ErrNotSupported
}

// Pause implements inet.Stack.Pause.
func (*Stack) Pause() {}

// Restore implements inet.Stack.Restore.
func (*Stack) Restore() {}

// Resume implements inet.Stack.Resume.
func (*Stack) Resume() {}

// RegisteredEndpoints implements inet.Stack.RegisteredEndpoints.
func (*Stack) RegisteredEndpoints() []stack.TransportEndpoint { return nil }

// CleanupEndpoints implements inet.Stack.CleanupEndpoints.
func (*Stack) CleanupEndpoints() []stack.TransportEndpoint { return nil }

// RestoreCleanupEndpoints implements inet.Stack.RestoreCleanupEndpoints.
func (*Stack) RestoreCleanupEndpoints([]stack.TransportEndpoint) {}

// SetForwarding implements inet.Stack.SetForwarding.
func (*Stack) SetForwarding(tcpip.NetworkProtocolNumber, bool) error {
	return linuxerr.EACCES
}

// PortRange implements inet.Stack.PortRange.
func (*Stack) PortRange() (uint16, uint16) {
	// Use the default Linux values per net/ipv4/af_inet.c:inet_init_net().
	return 32768, 60999
}

// SetPortRange implements inet.Stack.SetPortRange.
func (*Stack) SetPortRange(uint16, uint16) error {
	return linuxerr.EACCES
}
