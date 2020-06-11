// Copyright 2020 The gVisor Authors.
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

package testbench

import (
	"context"
	"flag"
	"fmt"
	"net"
	"strconv"
	"syscall"
	"testing"

	pb "gvisor.dev/gvisor/test/packetimpact/proto/posix_server_go_proto"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
	"gvisor.dev/gvisor/pkg/tcpip"
)

// CMsg stores all data that can be found in control messages. For example, the
// ttl field stores the integer value found in the IP_TTL control message.
type CMsg struct {
	ifIndex uint32
	addr    *tcpip.Address

	// IPv4-specific
	specDst     *tcpip.Address
	origDstAddr *unix.SockaddrInet4
	tos         *uint8
	ttl         *uint8

	// IPv6-specific
	hopLimit *uint8
}

// SetPacketInfo adds a IP_PKTINFO or IPV6_PKTINFO control message.
//
// If no local source address needs to be specified, the ANY address for IPv4
// or IPv6 MUST be passed so that the IP version can be inferred. Note also
// that even though the IP_PKTINFO control message has two address fields, only
// one of them is relevant for sendmsg() and set via this method.
func (cmsg *CMsg) SetPacketInfo(ifIndex uint32, localAddr *tcpip.Address) error {
	cmsg.ifIndex = ifIndex
	if len(*localAddr) == 4 {
		cmsg.specDst = localAddr
	} else if len(*localAddr) == 16 {
		cmsg.addr = localAddr
	} else {
		return fmt.Errorf("localAddr=%v is not a valid IPv4 or IPv6 address", *localAddr)
	}
	return nil
}

// IPPktInfo gets the contents of a IP_PKTINFO control message, which includes:
// 1. the local interface ID the packet was received through,
// 2. the local address the packet was received through, and
// 3. the destination address in the IPv4 header of the packet (usually but
//    not necessarily equal to the local address).
func (cmsg *CMsg) IPPktInfo() (uint32, *tcpip.Address, *tcpip.Address, error) {
	if len(*cmsg.specDst) != 4 || len(*cmsg.addr) != 4 {
		return 0, nil, nil, fmt.Errorf("failed to find IP_PKTINFO control message")
	}
	return cmsg.ifIndex, cmsg.specDst, cmsg.addr, nil
}

// IPv6PktInfo gets the contents of a IPV6_PKTINFO control message, which
// includes:
// 1. the local interface ID the packet was received through, and
// 2. the destination address in the IPv6 header of the packet.
func (cmsg *CMsg) IPv6PktInfo() (uint32, *tcpip.Address, error) {
	if len(*cmsg.addr) != 16 {
		return 0, nil, fmt.Errorf("failed to find IPV6_PKTINFO control message")
	}
	return cmsg.ifIndex, cmsg.addr, nil
}

// OrigDstAddr gets the original destination address in a IP_ORIGDSTADDR
// control message.
func (cmsg *CMsg) OrigDstAddr() (*unix.SockaddrInet4, error) {
	if cmsg.origDstAddr == nil {
		return nil, fmt.Errorf("failed to find IP_ORIGDSTADDR control message")
	}
	return cmsg.origDstAddr, nil
}

// SetTOS adds a IP_TOS control message.
func (cmsg *CMsg) SetTOS(tos uint8) {
	cmsg.tos = &tos
}

// TOS gets the TOS value in a IP_TOS control message.
func (cmsg *CMsg) TOS() (uint8, error) {
	if cmsg.tos == nil {
		return 0, fmt.Errorf("failed to find TOS control message")
	}
	return *cmsg.tos, nil
}

// SetTTL adds a IP_TTL control message.
func (cmsg *CMsg) SetTTL(ttl uint8) {
	cmsg.ttl = &ttl
}

// TTL gets the TTL value in a IP_TTL control message.
func (cmsg *CMsg) TTL() (uint8, error) {
	if cmsg.ttl == nil {
		return 0, fmt.Errorf("failed to find IP_TTL control message")
	}
	return *cmsg.ttl, nil
}

// SetHopLimit adds a IPV6_HOPLIMIT control message.
func (cmsg *CMsg) SetHopLimit(hopLimit uint8) {
	cmsg.hopLimit = &hopLimit
}

// HopLimit gets the hop limit from a IPV6_HOPLIMIT control message.
func (cmsg *CMsg) HopLimit() (uint8, error) {
	if cmsg.hopLimit == nil {
		return 0, fmt.Errorf("failed to find Hop Limit control message")
	}
	return *cmsg.hopLimit, nil
}

func (cmsg *CMsg) toProto() ([]*pb.CMsg, error) {
	var proto []*pb.CMsg

	if cmsg.specDst != nil {
		proto = append(proto, &pb.CMsg{
			Cmsg: &pb.CMsg_IpPktinfo{
				&pb.CMsg_InPktInfo{
					Ifindex: cmsg.ifIndex,
					SpecDst: []byte(*cmsg.specDst),
				},
			},
		})
	} else if cmsg.addr != nil {
		proto = append(proto, &pb.CMsg{
			Cmsg: &pb.CMsg_Ipv6Pktinfo{
				&pb.CMsg_In6PktInfo{
					Ifindex: cmsg.ifIndex,
					Addr:    []byte(*cmsg.addr),
				},
			},
		})
	}

	if cmsg.tos != nil {
		proto = append(proto, &pb.CMsg{Cmsg: &pb.CMsg_IpTos{uint32(*cmsg.tos)}})
	}

	if cmsg.ttl != nil {
		proto = append(proto, &pb.CMsg{Cmsg: &pb.CMsg_IpTtl{int32(*cmsg.ttl)}})
	}

	if cmsg.hopLimit != nil {
		proto = append(proto, &pb.CMsg{Cmsg: &pb.CMsg_Ipv6Hoplimit{int32(*cmsg.hopLimit)}})
	}

	return proto, nil
}

func protoToCMsg(proto []*pb.CMsg) (*CMsg, error) {
	var cmsg CMsg
	for _, cmsgProto := range proto {
		switch m := cmsgProto.Cmsg.(type) {
		case *pb.CMsg_IpPktinfo:
			cmsg.ifIndex = m.IpPktinfo.GetIfindex()
			cmsg.specDst = Address(tcpip.Address(m.IpPktinfo.GetSpecDst()))
			cmsg.addr = Address(tcpip.Address(m.IpPktinfo.GetAddr()))
			if len(*cmsg.specDst) != 4 || len(*cmsg.addr) != 4 {
				return nil, fmt.Errorf("invalid address in IP_PKTINFO message: specDst=%v, addr=%v", m.IpPktinfo.GetSpecDst(), m.IpPktinfo.GetAddr())
			}
		case *pb.CMsg_Ipv6Pktinfo:
			cmsg.ifIndex = m.Ipv6Pktinfo.GetIfindex()
			cmsg.addr = Address(tcpip.Address(m.Ipv6Pktinfo.GetAddr()))
			if len(*cmsg.addr) != 16 {
				return nil, fmt.Errorf("invalid address in IPV6_PKTINFO message: addr=%v", m.Ipv6Pktinfo.GetAddr())
			}
		case *pb.CMsg_IpOrigdstaddr:
			cmsg.origDstAddr = &unix.SockaddrInet4{
				Port: int(m.IpOrigdstaddr.GetPort()),
			}
			copy(cmsg.origDstAddr.Addr[:], m.IpOrigdstaddr.GetAddr())
		case *pb.CMsg_IpTos:
			cmsg.tos = Uint8(uint8(m.IpTos))
		case *pb.CMsg_IpTtl:
			cmsg.ttl = Uint8(uint8(m.IpTtl))
		case *pb.CMsg_Ipv6Hoplimit:
			cmsg.hopLimit = Uint8(uint8(m.Ipv6Hoplimit))
		default:
			return nil, fmt.Errorf("invalid control message type=%T", cmsgProto.Cmsg)
		}
	}
	return &cmsg, nil
}

// DUT communicates with the DUT to force it to make POSIX calls.
type DUT struct {
	t           *testing.T
	conn        *grpc.ClientConn
	posixServer POSIXClient
}

// NewDUT creates a new connection with the DUT over gRPC.
func NewDUT(t *testing.T) DUT {
	flag.Parse()
	if err := genPseudoFlags(); err != nil {
		t.Fatal("generating psuedo flags:", err)
	}

	posixServerAddress := POSIXServerIP + ":" + strconv.Itoa(POSIXServerPort)
	conn, err := grpc.Dial(posixServerAddress, grpc.WithInsecure(), grpc.WithKeepaliveParams(keepalive.ClientParameters{Timeout: RPCKeepalive}))
	if err != nil {
		t.Fatalf("failed to grpc.Dial(%s): %s", posixServerAddress, err)
	}
	posixServer := NewPOSIXClient(conn)
	return DUT{
		t:           t,
		conn:        conn,
		posixServer: posixServer,
	}
}

// TearDown closes the underlying connection.
func (dut *DUT) TearDown() {
	dut.conn.Close()
}

func (dut *DUT) sockaddrToProto(sa unix.Sockaddr) *pb.Sockaddr {
	dut.t.Helper()
	switch s := sa.(type) {
	case *unix.SockaddrInet4:
		return &pb.Sockaddr{
			Sockaddr: &pb.Sockaddr_In{
				In: &pb.SockaddrIn{
					Family: unix.AF_INET,
					Port:   uint32(s.Port),
					Addr:   s.Addr[:],
				},
			},
		}
	case *unix.SockaddrInet6:
		return &pb.Sockaddr{
			Sockaddr: &pb.Sockaddr_In6{
				In6: &pb.SockaddrIn6{
					Family:   unix.AF_INET6,
					Port:     uint32(s.Port),
					Flowinfo: 0,
					ScopeId:  s.ZoneId,
					Addr:     s.Addr[:],
				},
			},
		}
	}
	dut.t.Fatalf("can't parse Sockaddr: %+v", sa)
	return nil
}

func (dut *DUT) protoToSockaddr(sa *pb.Sockaddr) unix.Sockaddr {
	dut.t.Helper()
	switch s := sa.Sockaddr.(type) {
	case *pb.Sockaddr_In:
		ret := unix.SockaddrInet4{
			Port: int(s.In.GetPort()),
		}
		copy(ret.Addr[:], s.In.GetAddr())
		return &ret
	case *pb.Sockaddr_In6:
		ret := unix.SockaddrInet6{
			Port:   int(s.In6.GetPort()),
			ZoneId: s.In6.GetScopeId(),
		}
		copy(ret.Addr[:], s.In6.GetAddr())
	}
	dut.t.Fatalf("can't parse Sockaddr: %+v", sa)
	return nil
}

// CreateBoundSocket makes a new socket on the DUT, with type typ and protocol
// proto, and bound to the IP address addr. Returns the new file descriptor and
// the port that was selected on the DUT.
func (dut *DUT) CreateBoundSocket(typ, proto int32, addr net.IP) (int32, uint16) {
	dut.t.Helper()
	var fd int32
	if addr.To4() != nil {
		fd = dut.Socket(unix.AF_INET, typ, proto)
		sa := unix.SockaddrInet4{}
		copy(sa.Addr[:], addr.To4())
		dut.Bind(fd, &sa)
	} else if addr.To16() != nil {
		fd = dut.Socket(unix.AF_INET6, typ, proto)
		sa := unix.SockaddrInet6{}
		copy(sa.Addr[:], addr.To16())
		dut.Bind(fd, &sa)
	} else {
		dut.t.Fatalf("unknown ip addr type for remoteIP")
	}
	sa := dut.GetSockName(fd)
	var port int
	switch s := sa.(type) {
	case *unix.SockaddrInet4:
		port = s.Port
	case *unix.SockaddrInet6:
		port = s.Port
	default:
		dut.t.Fatalf("unknown sockaddr type from getsockname: %t", sa)
	}
	return fd, uint16(port)
}

// CreateListener makes a new TCP connection. If it fails, the test ends.
func (dut *DUT) CreateListener(typ, proto, backlog int32) (int32, uint16) {
	fd, remotePort := dut.CreateBoundSocket(typ, proto, net.ParseIP(RemoteIPv4))
	dut.Listen(fd, backlog)
	return fd, remotePort
}

// All the functions that make gRPC calls to the POSIX service are below, sorted
// alphabetically.

// Accept calls accept on the DUT and causes a fatal test failure if it doesn't
// succeed. If more control over the timeout or error handling is needed, use
// AcceptWithErrno.
func (dut *DUT) Accept(sockfd int32) (int32, unix.Sockaddr) {
	dut.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), RPCTimeout)
	defer cancel()
	fd, sa, err := dut.AcceptWithErrno(ctx, sockfd)
	if fd < 0 {
		dut.t.Fatalf("failed to accept: %s", err)
	}
	return fd, sa
}

// AcceptWithErrno calls accept on the DUT.
func (dut *DUT) AcceptWithErrno(ctx context.Context, sockfd int32) (int32, unix.Sockaddr, error) {
	dut.t.Helper()
	req := pb.AcceptRequest{
		Sockfd: sockfd,
	}
	resp, err := dut.posixServer.Accept(ctx, &req)
	if err != nil {
		dut.t.Fatalf("failed to call Accept: %s", err)
	}
	return resp.GetFd(), dut.protoToSockaddr(resp.GetAddr()), syscall.Errno(resp.GetErrno_())
}

// Bind calls bind on the DUT and causes a fatal test failure if it doesn't
// succeed. If more control over the timeout or error handling is
// needed, use BindWithErrno.
func (dut *DUT) Bind(fd int32, sa unix.Sockaddr) {
	dut.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), RPCTimeout)
	defer cancel()
	ret, err := dut.BindWithErrno(ctx, fd, sa)
	if ret != 0 {
		dut.t.Fatalf("failed to bind socket: %s", err)
	}
}

// BindWithErrno calls bind on the DUT.
func (dut *DUT) BindWithErrno(ctx context.Context, fd int32, sa unix.Sockaddr) (int32, error) {
	dut.t.Helper()
	req := pb.BindRequest{
		Sockfd: fd,
		Addr:   dut.sockaddrToProto(sa),
	}
	resp, err := dut.posixServer.Bind(ctx, &req)
	if err != nil {
		dut.t.Fatalf("failed to call Bind: %s", err)
	}
	return resp.GetRet(), syscall.Errno(resp.GetErrno_())
}

// Close calls close on the DUT and causes a fatal test failure if it doesn't
// succeed. If more control over the timeout or error handling is needed, use
// CloseWithErrno.
func (dut *DUT) Close(fd int32) {
	dut.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), RPCTimeout)
	defer cancel()
	ret, err := dut.CloseWithErrno(ctx, fd)
	if ret != 0 {
		dut.t.Fatalf("failed to close: %s", err)
	}
}

// CloseWithErrno calls close on the DUT.
func (dut *DUT) CloseWithErrno(ctx context.Context, fd int32) (int32, error) {
	dut.t.Helper()
	req := pb.CloseRequest{
		Fd: fd,
	}
	resp, err := dut.posixServer.Close(ctx, &req)
	if err != nil {
		dut.t.Fatalf("failed to call Close: %s", err)
	}
	return resp.GetRet(), syscall.Errno(resp.GetErrno_())
}

// Connect calls connect on the DUT and causes a fatal test failure if it
// doesn't succeed. If more control over the timeout or error handling is
// needed, use ConnectWithErrno.
func (dut *DUT) Connect(fd int32, sa unix.Sockaddr) {
	dut.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), RPCTimeout)
	defer cancel()
	ret, err := dut.ConnectWithErrno(ctx, fd, sa)
	// Ignore 'operation in progress' error that can be returned when the socket
	// is non-blocking.
	if err != syscall.Errno(unix.EINPROGRESS) && ret != 0 {
		dut.t.Fatalf("failed to connect socket: %s", err)
	}
}

// ConnectWithErrno calls bind on the DUT.
func (dut *DUT) ConnectWithErrno(ctx context.Context, fd int32, sa unix.Sockaddr) (int32, error) {
	dut.t.Helper()
	req := pb.ConnectRequest{
		Sockfd: fd,
		Addr:   dut.sockaddrToProto(sa),
	}
	resp, err := dut.posixServer.Connect(ctx, &req)
	if err != nil {
		dut.t.Fatalf("failed to call Connect: %s", err)
	}
	return resp.GetRet(), syscall.Errno(resp.GetErrno_())
}

// Fcntl calls fcntl on the DUT and causes a fatal test failure if it
// doesn't succeed. If more control over the timeout or error handling is
// needed, use FcntlWithErrno.
func (dut *DUT) Fcntl(fd, cmd, arg int32) int32 {
	dut.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), RPCTimeout)
	defer cancel()
	ret, err := dut.FcntlWithErrno(ctx, fd, cmd, arg)
	if ret == -1 {
		dut.t.Fatalf("failed to Fcntl: ret=%d, errno=%s", ret, err)
	}
	return ret
}

// FcntlWithErrno calls fcntl on the DUT.
func (dut *DUT) FcntlWithErrno(ctx context.Context, fd, cmd, arg int32) (int32, error) {
	dut.t.Helper()
	req := pb.FcntlRequest{
		Fd:  fd,
		Cmd: cmd,
		Arg: arg,
	}
	resp, err := dut.posixServer.Fcntl(ctx, &req)
	if err != nil {
		dut.t.Fatalf("failed to call Fcntl: %s", err)
	}
	return resp.GetRet(), syscall.Errno(resp.GetErrno_())
}

// GetSockName calls getsockname on the DUT and causes a fatal test failure if
// it doesn't succeed. If more control over the timeout or error handling is
// needed, use GetSockNameWithErrno.
func (dut *DUT) GetSockName(sockfd int32) unix.Sockaddr {
	dut.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), RPCTimeout)
	defer cancel()
	ret, sa, err := dut.GetSockNameWithErrno(ctx, sockfd)
	if ret != 0 {
		dut.t.Fatalf("failed to getsockname: %s", err)
	}
	return sa
}

// GetSockNameWithErrno calls getsockname on the DUT.
func (dut *DUT) GetSockNameWithErrno(ctx context.Context, sockfd int32) (int32, unix.Sockaddr, error) {
	dut.t.Helper()
	req := pb.GetSockNameRequest{
		Sockfd: sockfd,
	}
	resp, err := dut.posixServer.GetSockName(ctx, &req)
	if err != nil {
		dut.t.Fatalf("failed to call Bind: %s", err)
	}
	return resp.GetRet(), dut.protoToSockaddr(resp.GetAddr()), syscall.Errno(resp.GetErrno_())
}

func (dut *DUT) getSockOpt(ctx context.Context, sockfd, level, optname, optlen int32, typ pb.GetSockOptRequest_SockOptType) (int32, *pb.SockOptVal, error) {
	dut.t.Helper()
	req := pb.GetSockOptRequest{
		Sockfd:  sockfd,
		Level:   level,
		Optname: optname,
		Optlen:  optlen,
		Type:    typ,
	}
	resp, err := dut.posixServer.GetSockOpt(ctx, &req)
	if err != nil {
		dut.t.Fatalf("failed to call GetSockOpt: %s", err)
	}
	optval := resp.GetOptval()
	if optval == nil {
		dut.t.Fatalf("GetSockOpt response does not contain a value")
	}
	return resp.GetRet(), optval, syscall.Errno(resp.GetErrno_())
}

// GetSockOpt calls getsockopt on the DUT and causes a fatal test failure if it
// doesn't succeed. If more control over the timeout or error handling is
// needed, use GetSockOptWithErrno. Because endianess and the width of values
// might differ between the testbench and DUT architectures, prefer to use a
// more specific GetSockOptXxx function.
func (dut *DUT) GetSockOpt(sockfd, level, optname, optlen int32) []byte {
	dut.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), RPCTimeout)
	defer cancel()
	ret, optval, err := dut.GetSockOptWithErrno(ctx, sockfd, level, optname, optlen)
	if ret != 0 {
		dut.t.Fatalf("failed to GetSockOpt: %s", err)
	}
	return optval
}

// GetSockOptWithErrno calls getsockopt on the DUT. Because endianess and the
// width of values might differ between the testbench and DUT architectures,
// prefer to use a more specific GetSockOptXxxWithErrno function.
func (dut *DUT) GetSockOptWithErrno(ctx context.Context, sockfd, level, optname, optlen int32) (int32, []byte, error) {
	dut.t.Helper()
	ret, optval, errno := dut.getSockOpt(ctx, sockfd, level, optname, optlen, pb.GetSockOptRequest_BYTES)
	bytesval, ok := optval.Val.(*pb.SockOptVal_Bytesval)
	if !ok {
		dut.t.Fatalf("GetSockOpt got value type: %T, want bytes", optval)
	}
	return ret, bytesval.Bytesval, errno
}

// GetSockOptInt calls getsockopt on the DUT and causes a fatal test failure
// if it doesn't succeed. If more control over the int optval or error handling
// is needed, use GetSockOptIntWithErrno.
func (dut *DUT) GetSockOptInt(sockfd, level, optname int32) int32 {
	dut.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), RPCTimeout)
	defer cancel()
	ret, intval, err := dut.GetSockOptIntWithErrno(ctx, sockfd, level, optname)
	if ret != 0 {
		dut.t.Fatalf("failed to GetSockOptInt: %s", err)
	}
	return intval
}

// GetSockOptIntWithErrno calls getsockopt with an integer optval.
func (dut *DUT) GetSockOptIntWithErrno(ctx context.Context, sockfd, level, optname int32) (int32, int32, error) {
	dut.t.Helper()
	ret, optval, errno := dut.getSockOpt(ctx, sockfd, level, optname, 0, pb.GetSockOptRequest_INT)
	intval, ok := optval.Val.(*pb.SockOptVal_Intval)
	if !ok {
		dut.t.Fatalf("GetSockOpt got value type: %T, want int", optval)
	}
	return ret, intval.Intval, errno
}

// GetSockOptTimeval calls getsockopt on the DUT and causes a fatal test failure
// if it doesn't succeed. If more control over the timeout or error handling is
// needed, use GetSockOptTimevalWithErrno.
func (dut *DUT) GetSockOptTimeval(sockfd, level, optname int32) unix.Timeval {
	dut.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), RPCTimeout)
	defer cancel()
	ret, timeval, err := dut.GetSockOptTimevalWithErrno(ctx, sockfd, level, optname)
	if ret != 0 {
		dut.t.Fatalf("failed to GetSockOptTimeval: %s", err)
	}
	return timeval
}

// GetSockOptTimevalWithErrno calls getsockopt and returns a timeval.
func (dut *DUT) GetSockOptTimevalWithErrno(ctx context.Context, sockfd, level, optname int32) (int32, unix.Timeval, error) {
	dut.t.Helper()
	ret, optval, errno := dut.getSockOpt(ctx, sockfd, level, optname, 0, pb.GetSockOptRequest_TIME)
	tv, ok := optval.Val.(*pb.SockOptVal_Timeval)
	if !ok {
		dut.t.Fatalf("GetSockOpt got value type: %T, want timeval", optval)
	}
	timeval := unix.Timeval{
		Sec:  tv.Timeval.Seconds,
		Usec: tv.Timeval.Microseconds,
	}
	return ret, timeval, errno
}

// Listen calls listen on the DUT and causes a fatal test failure if it doesn't
// succeed. If more control over the timeout or error handling is needed, use
// ListenWithErrno.
func (dut *DUT) Listen(sockfd, backlog int32) {
	dut.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), RPCTimeout)
	defer cancel()
	ret, err := dut.ListenWithErrno(ctx, sockfd, backlog)
	if ret != 0 {
		dut.t.Fatalf("failed to listen: %s", err)
	}
}

// ListenWithErrno calls listen on the DUT.
func (dut *DUT) ListenWithErrno(ctx context.Context, sockfd, backlog int32) (int32, error) {
	dut.t.Helper()
	req := pb.ListenRequest{
		Sockfd:  sockfd,
		Backlog: backlog,
	}
	resp, err := dut.posixServer.Listen(ctx, &req)
	if err != nil {
		dut.t.Fatalf("failed to call Listen: %s", err)
	}
	return resp.GetRet(), syscall.Errno(resp.GetErrno_())
}

// Send calls send on the DUT and causes a fatal test failure if it doesn't
// succeed. If more control over the timeout or error handling is needed, use
// SendWithErrno.
func (dut *DUT) Send(sockfd int32, buf []byte, flags int32) int32 {
	dut.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), RPCTimeout)
	defer cancel()
	ret, err := dut.SendWithErrno(ctx, sockfd, buf, flags)
	if ret == -1 {
		dut.t.Fatalf("failed to send: %s", err)
	}
	return ret
}

// SendWithErrno calls send on the DUT.
func (dut *DUT) SendWithErrno(ctx context.Context, sockfd int32, buf []byte, flags int32) (int32, error) {
	dut.t.Helper()
	req := pb.SendRequest{
		Sockfd: sockfd,
		Buf:    buf,
		Flags:  flags,
	}
	resp, err := dut.posixServer.Send(ctx, &req)
	if err != nil {
		dut.t.Fatalf("failed to call Send: %s", err)
	}
	return resp.GetRet(), syscall.Errno(resp.GetErrno_())
}

// SendMsg calls sendmsg on the DUT and causes a fatal test failure if it
// doesn't succeed. If more control over the timeout or error handling is
// needed, use SendMsgWithErrno.
func (dut *DUT) SendMsg(sockfd int32, destAddr unix.Sockaddr, iov [][]byte, control *CMsg, flags int32) int32 {
	dut.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), RPCTimeout)
	defer cancel()
	ret, err := dut.SendMsgWithErrno(ctx, sockfd, destAddr, iov, control, flags)
	if ret == -1 {
		dut.t.Fatalf("failed to sendmsg: %s", err)
	}
	return ret
}

// SendMsgWithErrno calls send on the DUT.
func (dut *DUT) SendMsgWithErrno(ctx context.Context, sockfd int32, destAddr unix.Sockaddr, iov [][]byte, control *CMsg, flags int32) (int32, error) {
	dut.t.Helper()
	cmsgProto, err := control.toProto()
	if err != nil {
		dut.t.Fatalf("failed to convert cmsg to protobuf message: %s", err)
	}
	req := pb.SendMsgRequest{
		Sockfd: sockfd,
		Msg: &pb.MsgHdr{
			Iov:     iov,
			Control: cmsgProto,
			Name:    dut.sockaddrToProto(destAddr),
		},
		Flags: flags,
	}
	resp, err := dut.posixServer.SendMsg(ctx, &req)
	if err != nil {
		dut.t.Fatalf("failed to call SendMsg: %s", err)
	}
	return resp.GetRet(), syscall.Errno(resp.GetErrno_())
}

// SendTo calls sendto on the DUT and causes a fatal test failure if it doesn't
// succeed. If more control over the timeout or error handling is needed, use
// SendToWithErrno.
func (dut *DUT) SendTo(sockfd int32, buf []byte, flags int32, destAddr unix.Sockaddr) int32 {
	dut.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), RPCTimeout)
	defer cancel()
	ret, err := dut.SendToWithErrno(ctx, sockfd, buf, flags, destAddr)
	if ret == -1 {
		dut.t.Fatalf("failed to sendto: %s", err)
	}
	return ret
}

// SendToWithErrno calls sendto on the DUT.
func (dut *DUT) SendToWithErrno(ctx context.Context, sockfd int32, buf []byte, flags int32, destAddr unix.Sockaddr) (int32, error) {
	dut.t.Helper()
	req := pb.SendToRequest{
		Sockfd:   sockfd,
		Buf:      buf,
		Flags:    flags,
		DestAddr: dut.sockaddrToProto(destAddr),
	}
	resp, err := dut.posixServer.SendTo(ctx, &req)
	if err != nil {
		dut.t.Fatalf("faled to call SendTo: %s", err)
	}
	return resp.GetRet(), syscall.Errno(resp.GetErrno_())
}

// SetNonBlocking will set O_NONBLOCK flag for fd if nonblocking
// is true, otherwise it will clear the flag.
func (dut *DUT) SetNonBlocking(fd int32, nonblocking bool) {
	dut.t.Helper()
	flags := dut.Fcntl(fd, unix.F_GETFL, 0)
	if nonblocking {
		flags |= unix.O_NONBLOCK
	} else {
		flags &= ^unix.O_NONBLOCK
	}
	dut.Fcntl(fd, unix.F_SETFL, flags)
}

func (dut *DUT) setSockOpt(ctx context.Context, sockfd, level, optname int32, optval *pb.SockOptVal) (int32, error) {
	dut.t.Helper()
	req := pb.SetSockOptRequest{
		Sockfd:  sockfd,
		Level:   level,
		Optname: optname,
		Optval:  optval,
	}
	resp, err := dut.posixServer.SetSockOpt(ctx, &req)
	if err != nil {
		dut.t.Fatalf("failed to call SetSockOpt: %s", err)
	}
	return resp.GetRet(), syscall.Errno(resp.GetErrno_())
}

// SetSockOpt calls setsockopt on the DUT and causes a fatal test failure if it
// doesn't succeed. If more control over the timeout or error handling is
// needed, use SetSockOptWithErrno. Because endianess and the width of values
// might differ between the testbench and DUT architectures, prefer to use a
// more specific SetSockOptXxx function.
func (dut *DUT) SetSockOpt(sockfd, level, optname int32, optval []byte) {
	dut.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), RPCTimeout)
	defer cancel()
	ret, err := dut.SetSockOptWithErrno(ctx, sockfd, level, optname, optval)
	if ret != 0 {
		dut.t.Fatalf("failed to SetSockOpt: %s", err)
	}
}

// SetSockOptWithErrno calls setsockopt on the DUT. Because endianess and the
// width of values might differ between the testbench and DUT architectures,
// prefer to use a more specific SetSockOptXxxWithErrno function.
func (dut *DUT) SetSockOptWithErrno(ctx context.Context, sockfd, level, optname int32, optval []byte) (int32, error) {
	dut.t.Helper()
	return dut.setSockOpt(ctx, sockfd, level, optname, &pb.SockOptVal{Val: &pb.SockOptVal_Bytesval{optval}})
}

// SetSockOptInt calls setsockopt on the DUT and causes a fatal test failure
// if it doesn't succeed. If more control over the int optval or error handling
// is needed, use SetSockOptIntWithErrno.
func (dut *DUT) SetSockOptInt(sockfd, level, optname, optval int32) {
	dut.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), RPCTimeout)
	defer cancel()
	ret, err := dut.SetSockOptIntWithErrno(ctx, sockfd, level, optname, optval)
	if ret != 0 {
		dut.t.Fatalf("failed to SetSockOptInt: %s", err)
	}
}

// SetSockOptIntWithErrno calls setsockopt with an integer optval.
func (dut *DUT) SetSockOptIntWithErrno(ctx context.Context, sockfd, level, optname, optval int32) (int32, error) {
	dut.t.Helper()
	return dut.setSockOpt(ctx, sockfd, level, optname, &pb.SockOptVal{Val: &pb.SockOptVal_Intval{optval}})
}

// SetSockOptTimeval calls setsockopt on the DUT and causes a fatal test failure
// if it doesn't succeed. If more control over the timeout or error handling is
// needed, use SetSockOptTimevalWithErrno.
func (dut *DUT) SetSockOptTimeval(sockfd, level, optname int32, tv *unix.Timeval) {
	dut.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), RPCTimeout)
	defer cancel()
	ret, err := dut.SetSockOptTimevalWithErrno(ctx, sockfd, level, optname, tv)
	if ret != 0 {
		dut.t.Fatalf("failed to SetSockOptTimeval: %s", err)
	}
}

// SetSockOptTimevalWithErrno calls setsockopt with the timeval converted to
// bytes.
func (dut *DUT) SetSockOptTimevalWithErrno(ctx context.Context, sockfd, level, optname int32, tv *unix.Timeval) (int32, error) {
	dut.t.Helper()
	timeval := pb.Timeval{
		Seconds:      int64(tv.Sec),
		Microseconds: int64(tv.Usec),
	}
	return dut.setSockOpt(ctx, sockfd, level, optname, &pb.SockOptVal{Val: &pb.SockOptVal_Timeval{&timeval}})
}

// Socket calls socket on the DUT and returns the file descriptor. If socket
// fails on the DUT, the test ends.
func (dut *DUT) Socket(domain, typ, proto int32) int32 {
	dut.t.Helper()
	fd, err := dut.SocketWithErrno(domain, typ, proto)
	if fd < 0 {
		dut.t.Fatalf("failed to create socket: %s", err)
	}
	return fd
}

// SocketWithErrno calls socket on the DUT and returns the fd and errno.
func (dut *DUT) SocketWithErrno(domain, typ, proto int32) (int32, error) {
	dut.t.Helper()
	req := pb.SocketRequest{
		Domain:   domain,
		Type:     typ,
		Protocol: proto,
	}
	ctx := context.Background()
	resp, err := dut.posixServer.Socket(ctx, &req)
	if err != nil {
		dut.t.Fatalf("failed to call Socket: %s", err)
	}
	return resp.GetFd(), syscall.Errno(resp.GetErrno_())
}

// Recv calls recv on the DUT and causes a fatal test failure if it doesn't
// succeed. If more control over the timeout or error handling is needed, use
// RecvWithErrno.
func (dut *DUT) Recv(sockfd, len, flags int32) []byte {
	dut.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), RPCTimeout)
	defer cancel()
	ret, buf, err := dut.RecvWithErrno(ctx, sockfd, len, flags)
	if ret == -1 {
		dut.t.Fatalf("failed to recv: %s", err)
	}
	return buf
}

// RecvWithErrno calls recv on the DUT.
func (dut *DUT) RecvWithErrno(ctx context.Context, sockfd, len, flags int32) (int32, []byte, error) {
	dut.t.Helper()
	req := pb.RecvRequest{
		Sockfd: sockfd,
		Len:    len,
		Flags:  flags,
	}
	resp, err := dut.posixServer.Recv(ctx, &req)
	if err != nil {
		dut.t.Fatalf("failed to call Recv: %s", err)
	}
	return resp.GetRet(), resp.GetBuf(), syscall.Errno(resp.GetErrno_())
}

// RecvMsg calls recvmsg on the DUT and causes a fatal test failure if it
// doesn't succeed. If more control over the timeout or error handling is
// needed, use RecvMsgWithErrno.
func (dut *DUT) RecvMsg(sockfd int32, iovlen []int32, controllen, flags int32) (unix.Sockaddr, [][]byte, *CMsg, int32) {
	dut.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), RPCTimeout)
	defer cancel()
	ret, srcAddr, iov, control, msgFlags, err := dut.RecvMsgWithErrno(ctx, sockfd, iovlen, controllen, flags)
	if ret == -1 {
		dut.t.Fatalf("failed to recvmsg: %s", err)
	}
	return srcAddr, iov, control, msgFlags
}

// RecvWithErrno calls recv on the DUT.
func (dut *DUT) RecvMsgWithErrno(ctx context.Context, sockfd int32, iovlen []int32, controllen, flags int32) (int32, unix.Sockaddr, [][]byte, *CMsg, int32, error) {
	dut.t.Helper()
	req := pb.RecvMsgRequest{
		Sockfd:     sockfd,
		Iovlen:     iovlen,
		Controllen: controllen,
		Flags:      flags,
	}
	resp, err := dut.posixServer.RecvMsg(ctx, &req)
	if err != nil {
		dut.t.Fatalf("failed to call RecvMsg: %s", err)
	}
	cmsg, err := protoToCMsg(resp.GetMsg().GetControl())
	if err != nil {
		dut.t.Fatalf("failed to convert protobuf cmsg: %s", err)
	}
	return resp.GetRet(), dut.protoToSockaddr(resp.GetMsg().GetName()), resp.GetMsg().GetIov(), cmsg, resp.GetMsg().GetFlags(), syscall.Errno(resp.GetErrno_())
}
