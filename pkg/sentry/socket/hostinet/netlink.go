// Copyright 2023 The gVisor Authors.
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
	"bytes"
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/binary"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/inet"
	"gvisor.dev/gvisor/pkg/tcpip"
)

func getInterfaces() (map[int32]inet.Interface, error) {
	data, err := syscall.NetlinkRIB(unix.RTM_GETLINK, syscall.AF_UNSPEC)
	if err != nil {
		return nil, err
	}
	msgs, err := syscall.ParseNetlinkMessage(data)
	if err != nil {
		return nil, err
	}
	ifs := make(map[int32]inet.Interface, len(msgs))
	for _, msg := range msgs {
		if msg.Header.Type != unix.RTM_NEWLINK {
			continue
		}
		if len(msg.Data) < unix.SizeofIfInfomsg {
			return nil, fmt.Errorf("RTM_GETLINK returned RTM_NEWLINK message with invalid data length (%d bytes, expected at least %d bytes)", len(msg.Data), unix.SizeofIfInfomsg)
		}
		var ifinfo linux.InterfaceInfoMessage
		ifinfo.UnmarshalUnsafe(msg.Data)
		inetIF := inet.Interface{
			DeviceType: ifinfo.Type,
			Flags:      ifinfo.Flags,
		}
		// Not clearly documented: syscall.ParseNetlinkRouteAttr will check the
		// syscall.NetlinkMessage.Header.Type and skip the struct ifinfomsg
		// accordingly.
		attrs, err := syscall.ParseNetlinkRouteAttr(&msg)
		if err != nil {
			return nil, fmt.Errorf("RTM_GETLINK returned RTM_NEWLINK message with invalid rtattrs: %v", err)
		}
		for _, attr := range attrs {
			switch attr.Attr.Type {
			case unix.IFLA_ADDRESS:
				inetIF.Addr = attr.Value
			case unix.IFLA_IFNAME:
				inetIF.Name = string(attr.Value[:len(attr.Value)-1])
			}
		}
		ifs[ifinfo.Index] = inetIF
	}
	return ifs, nil
}

func getInterfaceAddrs() (map[int32][]inet.InterfaceAddr, error) {
	data, err := syscall.NetlinkRIB(unix.RTM_GETADDR, syscall.AF_UNSPEC)
	if err != nil {
		return nil, err
	}
	msgs, err := syscall.ParseNetlinkMessage(data)
	if err != nil {
		return nil, err
	}
	addrs := make(map[int32][]inet.InterfaceAddr, len(msgs))
	for _, msg := range msgs {
		if msg.Header.Type != unix.RTM_NEWADDR {
			continue
		}
		if len(msg.Data) < unix.SizeofIfAddrmsg {
			return nil, fmt.Errorf("RTM_GETADDR returned RTM_NEWADDR message with invalid data length (%d bytes, expected at least %d bytes)", len(msg.Data), unix.SizeofIfAddrmsg)
		}
		var ifaddr linux.InterfaceAddrMessage
		ifaddr.UnmarshalUnsafe(msg.Data)
		inetAddr := inet.InterfaceAddr{
			Family:    ifaddr.Family,
			PrefixLen: ifaddr.PrefixLen,
			Flags:     ifaddr.Flags,
		}
		attrs, err := syscall.ParseNetlinkRouteAttr(&msg)
		if err != nil {
			return nil, fmt.Errorf("RTM_GETADDR returned RTM_NEWADDR message with invalid rtattrs: %v", err)
		}
		for _, attr := range attrs {
			switch attr.Attr.Type {
			case unix.IFA_ADDRESS:
				inetAddr.Addr = attr.Value
			}
		}
		addrs[int32(ifaddr.Index)] = append(addrs[int32(ifaddr.Index)], inetAddr)

	}
	return addrs, nil
}

func getRoutes() ([]inet.Route, error) {
	data, err := syscall.NetlinkRIB(unix.RTM_GETROUTE, syscall.AF_UNSPEC)
	if err != nil {
		return nil, err
	}
	msgs, err := syscall.ParseNetlinkMessage(data)
	if err != nil {
		return nil, err
	}
	routes, err := extractRoutes(msgs)
	if err != nil {
		return nil, err
	}

	return routes, nil
}

// extractRoutes populates the given routes slice with the data from the host
// route table.
func extractRoutes(routeMsgs []syscall.NetlinkMessage) ([]inet.Route, error) {
	var routes []inet.Route
	for _, routeMsg := range routeMsgs {
		if routeMsg.Header.Type != unix.RTM_NEWROUTE {
			continue
		}

		var ifRoute linux.RouteMessage
		ifRoute.UnmarshalUnsafe(routeMsg.Data)
		inetRoute := inet.Route{
			Family:   ifRoute.Family,
			DstLen:   ifRoute.DstLen,
			SrcLen:   ifRoute.SrcLen,
			TOS:      ifRoute.TOS,
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
			case unix.RTA_DST:
				inetRoute.DstAddr = attr.Value
			case unix.RTA_SRC:
				inetRoute.SrcAddr = attr.Value
			case unix.RTA_GATEWAY:
				inetRoute.GatewayAddr = attr.Value
			case unix.RTA_OIF:
				expected := int(binary.Size(inetRoute.OutputInterface))
				if len(attr.Value) != expected {
					return nil, fmt.Errorf("RTM_GETROUTE returned RTM_NEWROUTE message with invalid attribute data length (%d bytes, expected %d bytes)", len(attr.Value), expected)
				}
				var outputIF primitive.Int32
				outputIF.UnmarshalUnsafe(attr.Value)
				inetRoute.OutputInterface = int32(outputIF)
			}
		}

		routes = append(routes, inetRoute)
	}

	return routes, nil
}

// doNetlinkRouteRequest is a more general form of syscall.NetlinkRIB that
// allows sending arbitrary (marshallable) structs to the netlink socket.
func doNetlinkRouteRequest(msgs []marshal.Marshallable) error {
	s, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer syscall.Close(s)
	sa := syscall.SockaddrNetlink{Family: unix.AF_NETLINK}
	if err := syscall.Bind(s, &sa); err != nil {
		return err
	}

	b := marshal.MarshalAll(msgs)
	if err := syscall.Sendto(s, b, 0, &sa); err != nil {
		return err
	}

	lsa, err := syscall.Getsockname(s)
	if err != nil {
		return err
	}
	lsanl, ok := lsa.(*syscall.SockaddrNetlink)
	if !ok {
		return linuxerr.EINVAL
	}
	rbNew := make([]byte, hostarch.PageSize)
done:
	for {
		rb := rbNew
		nr, _, err := syscall.Recvfrom(s, rb, 0)
		if err != nil {
			return err
		}
		if nr < linux.NetlinkMessageHeaderSize {
			return linuxerr.EINVAL
		}
		rb = rb[:nr]
		msgs, err := syscall.ParseNetlinkMessage(rb)
		if err != nil {
			return err
		}
		for _, m := range msgs {
			if m.Header.Seq != 1 || m.Header.Pid != lsanl.Pid {
				return linuxerr.EINVAL
			}
			if m.Header.Type == linux.NLMSG_DONE {
				break done
			}
			if m.Header.Type == linux.NLMSG_ERROR {
				errno, err := binary.ReadUint32(bytes.NewReader(m.Data[0:4]), hostarch.ByteOrder)
				if err != nil {
					return err
				}
				if errno == 0 {
					break done
				}
				return linuxerr.ErrorFromUnix(unix.Errno(-errno))
			}
		}
	}
	return nil
}

func removeInterface(idx int32) error {
	// [ NetlinkMessageHeader | InterfaceInfoMessage ]
	hdr := linux.NetlinkMessageHeader{
		Type:  linux.RTM_DELLINK,
		Flags: linux.NLM_F_REQUEST | linux.NLM_F_ACK,
		Seq:   1,
	}
	infoMsg := linux.InterfaceInfoMessage{
		Family: linux.AF_UNSPEC,
		Index:  idx,
	}

	msgs := []marshal.Marshallable{
		&hdr,
		&infoMsg,
	}
	hdr.Length = uint32(marshal.TotalSize(msgs))
	return doNetlinkRouteRequest(msgs)
}

func doNetlinkInterfaceRequest(typ, flags uint16, idx uint32, addr inet.InterfaceAddr) error {
	// [ NetlinkMessageHeader | InterfaceAddrMessage | RtAttr | localAddr | RtAttr | peerAddr ]
	hdr := linux.NetlinkMessageHeader{
		Type:  typ,
		Flags: flags | linux.NLM_F_REQUEST | linux.NLM_F_ACK,
		Seq:   1,
	}
	infoMsg := linux.InterfaceAddrMessage{
		Family:    addr.Family,
		Index:     idx,
		PrefixLen: addr.PrefixLen,
		Flags:     addr.Flags,
	}
	// Local address.
	localAddr := tcpip.AddrFromSlice(addr.Addr)
	if addr.Family == linux.AF_INET {
		localAddr = localAddr.To4()
	}
	rtLocal := linux.RtAttr{
		Len:  linux.SizeOfRtAttr + uint16(localAddr.Len()),
		Type: linux.IFA_LOCAL,
	}
	localAddrBs := primitive.ByteSlice(localAddr.AsSlice())
	// Peer is always the local address for us.
	rtPeer := linux.RtAttr{
		Len:  linux.SizeOfRtAttr + uint16(localAddr.Len()),
		Type: linux.IFA_ADDRESS,
	}
	peerAddrBs := primitive.ByteSlice(localAddr.AsSlice())

	msgs := []marshal.Marshallable{
		&hdr,
		&infoMsg,
		&rtLocal,
		&localAddrBs,
		&rtPeer,
		&peerAddrBs,
	}
	hdr.Length = uint32(marshal.TotalSize(msgs))
	return doNetlinkRouteRequest(msgs)
}

func addInterfaceAddr(idx int32, addr inet.InterfaceAddr) error {
	return doNetlinkInterfaceRequest(linux.RTM_NEWADDR, linux.NLM_F_CREATE, uint32(idx), addr)
}

func removeInterfaceAddr(idx int32, addr inet.InterfaceAddr) error {
	return doNetlinkInterfaceRequest(linux.RTM_DELADDR, 0, uint32(idx), addr)
}
