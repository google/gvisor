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
	"encoding/binary"
	"flag"
	"net"
	"strconv"
	"syscall"
	"testing"
	"time"

	pb "gvisor.dev/gvisor/test/packetimpact/proto/posix_server_go_proto"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
)

// DUT communicates with the DUT to force it to make POSIX calls.
type DUT struct {
	conn        *grpc.ClientConn
	posixServer POSIXClient
}

// NewDUT creates a new connection with the DUT over gRPC.
func NewDUT(t *testing.T) DUT {
	t.Helper()

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
		conn:        conn,
		posixServer: posixServer,
	}
}

// TearDown closes the underlying connection.
func (dut *DUT) TearDown() {
	dut.conn.Close()
}

func (dut *DUT) sockaddrToProto(t *testing.T, sa unix.Sockaddr) *pb.Sockaddr {
	t.Helper()

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
	t.Fatalf("can't parse Sockaddr struct: %+v", sa)
	return nil
}

func (dut *DUT) protoToSockaddr(t *testing.T, sa *pb.Sockaddr) unix.Sockaddr {
	t.Helper()

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
		return &ret
	}
	t.Fatalf("can't parse Sockaddr proto: %#v", sa)
	return nil
}

// CreateBoundSocket makes a new socket on the DUT, with type typ and protocol
// proto, and bound to the IP address addr. Returns the new file descriptor and
// the port that was selected on the DUT.
func (dut *DUT) CreateBoundSocket(t *testing.T, typ, proto int32, addr net.IP) (int32, uint16) {
	t.Helper()

	var fd int32
	if addr.To4() != nil {
		fd = dut.Socket(t, unix.AF_INET, typ, proto)
		sa := unix.SockaddrInet4{}
		copy(sa.Addr[:], addr.To4())
		dut.Bind(t, fd, &sa)
	} else if addr.To16() != nil {
		fd = dut.Socket(t, unix.AF_INET6, typ, proto)
		sa := unix.SockaddrInet6{}
		copy(sa.Addr[:], addr.To16())
		sa.ZoneId = uint32(RemoteInterfaceID)
		dut.Bind(t, fd, &sa)
	} else {
		t.Fatalf("invalid IP address: %s", addr)
	}
	sa := dut.GetSockName(t, fd)
	var port int
	switch s := sa.(type) {
	case *unix.SockaddrInet4:
		port = s.Port
	case *unix.SockaddrInet6:
		port = s.Port
	default:
		t.Fatalf("unknown sockaddr type from getsockname: %T", sa)
	}
	return fd, uint16(port)
}

// CreateListener makes a new TCP connection. If it fails, the test ends.
func (dut *DUT) CreateListener(t *testing.T, typ, proto, backlog int32) (int32, uint16) {
	t.Helper()

	fd, remotePort := dut.CreateBoundSocket(t, typ, proto, net.ParseIP(RemoteIPv4))
	dut.Listen(t, fd, backlog)
	return fd, remotePort
}

// All the functions that make gRPC calls to the POSIX service are below, sorted
// alphabetically.

// Accept calls accept on the DUT and causes a fatal test failure if it doesn't
// succeed. If more control over the timeout or error handling is needed, use
// AcceptWithErrno.
func (dut *DUT) Accept(t *testing.T, sockfd int32) (int32, unix.Sockaddr) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), RPCTimeout)
	defer cancel()
	fd, sa, err := dut.AcceptWithErrno(ctx, t, sockfd)
	if fd < 0 {
		t.Fatalf("failed to accept: %s", err)
	}
	return fd, sa
}

// AcceptWithErrno calls accept on the DUT.
func (dut *DUT) AcceptWithErrno(ctx context.Context, t *testing.T, sockfd int32) (int32, unix.Sockaddr, error) {
	t.Helper()

	req := pb.AcceptRequest{
		Sockfd: sockfd,
	}
	resp, err := dut.posixServer.Accept(ctx, &req)
	if err != nil {
		t.Fatalf("failed to call Accept: %s", err)
	}
	return resp.GetFd(), dut.protoToSockaddr(t, resp.GetAddr()), syscall.Errno(resp.GetErrno_())
}

// Bind calls bind on the DUT and causes a fatal test failure if it doesn't
// succeed. If more control over the timeout or error handling is
// needed, use BindWithErrno.
func (dut *DUT) Bind(t *testing.T, fd int32, sa unix.Sockaddr) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), RPCTimeout)
	defer cancel()
	ret, err := dut.BindWithErrno(ctx, t, fd, sa)
	if ret != 0 {
		t.Fatalf("failed to bind socket: %s", err)
	}
}

// BindWithErrno calls bind on the DUT.
func (dut *DUT) BindWithErrno(ctx context.Context, t *testing.T, fd int32, sa unix.Sockaddr) (int32, error) {
	t.Helper()

	req := pb.BindRequest{
		Sockfd: fd,
		Addr:   dut.sockaddrToProto(t, sa),
	}
	resp, err := dut.posixServer.Bind(ctx, &req)
	if err != nil {
		t.Fatalf("failed to call Bind: %s", err)
	}
	return resp.GetRet(), syscall.Errno(resp.GetErrno_())
}

// Close calls close on the DUT and causes a fatal test failure if it doesn't
// succeed. If more control over the timeout or error handling is needed, use
// CloseWithErrno.
func (dut *DUT) Close(t *testing.T, fd int32) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), RPCTimeout)
	defer cancel()
	ret, err := dut.CloseWithErrno(ctx, t, fd)
	if ret != 0 {
		t.Fatalf("failed to close: %s", err)
	}
}

// CloseWithErrno calls close on the DUT.
func (dut *DUT) CloseWithErrno(ctx context.Context, t *testing.T, fd int32) (int32, error) {
	t.Helper()

	req := pb.CloseRequest{
		Fd: fd,
	}
	resp, err := dut.posixServer.Close(ctx, &req)
	if err != nil {
		t.Fatalf("failed to call Close: %s", err)
	}
	return resp.GetRet(), syscall.Errno(resp.GetErrno_())
}

// Connect calls connect on the DUT and causes a fatal test failure if it
// doesn't succeed. If more control over the timeout or error handling is
// needed, use ConnectWithErrno.
func (dut *DUT) Connect(t *testing.T, fd int32, sa unix.Sockaddr) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), RPCTimeout)
	defer cancel()
	ret, err := dut.ConnectWithErrno(ctx, t, fd, sa)
	// Ignore 'operation in progress' error that can be returned when the socket
	// is non-blocking.
	if err != syscall.Errno(unix.EINPROGRESS) && ret != 0 {
		t.Fatalf("failed to connect socket: %s", err)
	}
}

// ConnectWithErrno calls bind on the DUT.
func (dut *DUT) ConnectWithErrno(ctx context.Context, t *testing.T, fd int32, sa unix.Sockaddr) (int32, error) {
	t.Helper()

	req := pb.ConnectRequest{
		Sockfd: fd,
		Addr:   dut.sockaddrToProto(t, sa),
	}
	resp, err := dut.posixServer.Connect(ctx, &req)
	if err != nil {
		t.Fatalf("failed to call Connect: %s", err)
	}
	return resp.GetRet(), syscall.Errno(resp.GetErrno_())
}

// Fcntl calls fcntl on the DUT and causes a fatal test failure if it
// doesn't succeed. If more control over the timeout or error handling is
// needed, use FcntlWithErrno.
func (dut *DUT) Fcntl(t *testing.T, fd, cmd, arg int32) int32 {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), RPCTimeout)
	defer cancel()
	ret, err := dut.FcntlWithErrno(ctx, t, fd, cmd, arg)
	if ret == -1 {
		t.Fatalf("failed to Fcntl: ret=%d, errno=%s", ret, err)
	}
	return ret
}

// FcntlWithErrno calls fcntl on the DUT.
func (dut *DUT) FcntlWithErrno(ctx context.Context, t *testing.T, fd, cmd, arg int32) (int32, error) {
	t.Helper()

	req := pb.FcntlRequest{
		Fd:  fd,
		Cmd: cmd,
		Arg: arg,
	}
	resp, err := dut.posixServer.Fcntl(ctx, &req)
	if err != nil {
		t.Fatalf("failed to call Fcntl: %s", err)
	}
	return resp.GetRet(), syscall.Errno(resp.GetErrno_())
}

// GetSockName calls getsockname on the DUT and causes a fatal test failure if
// it doesn't succeed. If more control over the timeout or error handling is
// needed, use GetSockNameWithErrno.
func (dut *DUT) GetSockName(t *testing.T, sockfd int32) unix.Sockaddr {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), RPCTimeout)
	defer cancel()
	ret, sa, err := dut.GetSockNameWithErrno(ctx, t, sockfd)
	if ret != 0 {
		t.Fatalf("failed to getsockname: %s", err)
	}
	return sa
}

// GetSockNameWithErrno calls getsockname on the DUT.
func (dut *DUT) GetSockNameWithErrno(ctx context.Context, t *testing.T, sockfd int32) (int32, unix.Sockaddr, error) {
	t.Helper()

	req := pb.GetSockNameRequest{
		Sockfd: sockfd,
	}
	resp, err := dut.posixServer.GetSockName(ctx, &req)
	if err != nil {
		t.Fatalf("failed to call Bind: %s", err)
	}
	return resp.GetRet(), dut.protoToSockaddr(t, resp.GetAddr()), syscall.Errno(resp.GetErrno_())
}

func (dut *DUT) getSockOpt(ctx context.Context, t *testing.T, sockfd, level, optname, optlen int32, typ pb.GetSockOptRequest_SockOptType) (int32, *pb.SockOptVal, error) {
	t.Helper()

	req := pb.GetSockOptRequest{
		Sockfd:  sockfd,
		Level:   level,
		Optname: optname,
		Optlen:  optlen,
		Type:    typ,
	}
	resp, err := dut.posixServer.GetSockOpt(ctx, &req)
	if err != nil {
		t.Fatalf("failed to call GetSockOpt: %s", err)
	}
	optval := resp.GetOptval()
	if optval == nil {
		t.Fatalf("GetSockOpt response does not contain a value")
	}
	return resp.GetRet(), optval, syscall.Errno(resp.GetErrno_())
}

// GetSockOpt calls getsockopt on the DUT and causes a fatal test failure if it
// doesn't succeed. If more control over the timeout or error handling is
// needed, use GetSockOptWithErrno. Because endianess and the width of values
// might differ between the testbench and DUT architectures, prefer to use a
// more specific GetSockOptXxx function.
func (dut *DUT) GetSockOpt(t *testing.T, sockfd, level, optname, optlen int32) []byte {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), RPCTimeout)
	defer cancel()
	ret, optval, err := dut.GetSockOptWithErrno(ctx, t, sockfd, level, optname, optlen)
	if ret != 0 {
		t.Fatalf("failed to GetSockOpt: %s", err)
	}
	return optval
}

// GetSockOptWithErrno calls getsockopt on the DUT. Because endianess and the
// width of values might differ between the testbench and DUT architectures,
// prefer to use a more specific GetSockOptXxxWithErrno function.
func (dut *DUT) GetSockOptWithErrno(ctx context.Context, t *testing.T, sockfd, level, optname, optlen int32) (int32, []byte, error) {
	t.Helper()

	ret, optval, errno := dut.getSockOpt(ctx, t, sockfd, level, optname, optlen, pb.GetSockOptRequest_BYTES)
	bytesval, ok := optval.Val.(*pb.SockOptVal_Bytesval)
	if !ok {
		t.Fatalf("GetSockOpt got value type: %T, want bytes", optval.Val)
	}
	return ret, bytesval.Bytesval, errno
}

// GetSockOptInt calls getsockopt on the DUT and causes a fatal test failure
// if it doesn't succeed. If more control over the int optval or error handling
// is needed, use GetSockOptIntWithErrno.
func (dut *DUT) GetSockOptInt(t *testing.T, sockfd, level, optname int32) int32 {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), RPCTimeout)
	defer cancel()
	ret, intval, err := dut.GetSockOptIntWithErrno(ctx, t, sockfd, level, optname)
	if ret != 0 {
		t.Fatalf("failed to GetSockOptInt: %s", err)
	}
	return intval
}

// GetSockOptIntWithErrno calls getsockopt with an integer optval.
func (dut *DUT) GetSockOptIntWithErrno(ctx context.Context, t *testing.T, sockfd, level, optname int32) (int32, int32, error) {
	t.Helper()

	ret, optval, errno := dut.getSockOpt(ctx, t, sockfd, level, optname, 0, pb.GetSockOptRequest_INT)
	intval, ok := optval.Val.(*pb.SockOptVal_Intval)
	if !ok {
		t.Fatalf("GetSockOpt got value type: %T, want int", optval.Val)
	}
	return ret, intval.Intval, errno
}

// GetSockOptTimeval calls getsockopt on the DUT and causes a fatal test failure
// if it doesn't succeed. If more control over the timeout or error handling is
// needed, use GetSockOptTimevalWithErrno.
func (dut *DUT) GetSockOptTimeval(t *testing.T, sockfd, level, optname int32) unix.Timeval {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), RPCTimeout)
	defer cancel()
	ret, timeval, err := dut.GetSockOptTimevalWithErrno(ctx, t, sockfd, level, optname)
	if ret != 0 {
		t.Fatalf("failed to GetSockOptTimeval: %s", err)
	}
	return timeval
}

// GetSockOptTimevalWithErrno calls getsockopt and returns a timeval.
func (dut *DUT) GetSockOptTimevalWithErrno(ctx context.Context, t *testing.T, sockfd, level, optname int32) (int32, unix.Timeval, error) {
	t.Helper()

	ret, optval, errno := dut.getSockOpt(ctx, t, sockfd, level, optname, 0, pb.GetSockOptRequest_TIME)
	tv, ok := optval.Val.(*pb.SockOptVal_Timeval)
	if !ok {
		t.Fatalf("GetSockOpt got value type: %T, want timeval", optval.Val)
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
func (dut *DUT) Listen(t *testing.T, sockfd, backlog int32) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), RPCTimeout)
	defer cancel()
	ret, err := dut.ListenWithErrno(ctx, t, sockfd, backlog)
	if ret != 0 {
		t.Fatalf("failed to listen: %s", err)
	}
}

// ListenWithErrno calls listen on the DUT.
func (dut *DUT) ListenWithErrno(ctx context.Context, t *testing.T, sockfd, backlog int32) (int32, error) {
	t.Helper()

	req := pb.ListenRequest{
		Sockfd:  sockfd,
		Backlog: backlog,
	}
	resp, err := dut.posixServer.Listen(ctx, &req)
	if err != nil {
		t.Fatalf("failed to call Listen: %s", err)
	}
	return resp.GetRet(), syscall.Errno(resp.GetErrno_())
}

// Send calls send on the DUT and causes a fatal test failure if it doesn't
// succeed. If more control over the timeout or error handling is needed, use
// SendWithErrno.
func (dut *DUT) Send(t *testing.T, sockfd int32, buf []byte, flags int32) int32 {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), RPCTimeout)
	defer cancel()
	ret, err := dut.SendWithErrno(ctx, t, sockfd, buf, flags)
	if ret == -1 {
		t.Fatalf("failed to send: %s", err)
	}
	return ret
}

// SendWithErrno calls send on the DUT.
func (dut *DUT) SendWithErrno(ctx context.Context, t *testing.T, sockfd int32, buf []byte, flags int32) (int32, error) {
	t.Helper()

	req := pb.SendRequest{
		Sockfd: sockfd,
		Buf:    buf,
		Flags:  flags,
	}
	resp, err := dut.posixServer.Send(ctx, &req)
	if err != nil {
		t.Fatalf("failed to call Send: %s", err)
	}
	return resp.GetRet(), syscall.Errno(resp.GetErrno_())
}

// SendTo calls sendto on the DUT and causes a fatal test failure if it doesn't
// succeed. If more control over the timeout or error handling is needed, use
// SendToWithErrno.
func (dut *DUT) SendTo(t *testing.T, sockfd int32, buf []byte, flags int32, destAddr unix.Sockaddr) int32 {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), RPCTimeout)
	defer cancel()
	ret, err := dut.SendToWithErrno(ctx, t, sockfd, buf, flags, destAddr)
	if ret == -1 {
		t.Fatalf("failed to sendto: %s", err)
	}
	return ret
}

// SendToWithErrno calls sendto on the DUT.
func (dut *DUT) SendToWithErrno(ctx context.Context, t *testing.T, sockfd int32, buf []byte, flags int32, destAddr unix.Sockaddr) (int32, error) {
	t.Helper()

	req := pb.SendToRequest{
		Sockfd:   sockfd,
		Buf:      buf,
		Flags:    flags,
		DestAddr: dut.sockaddrToProto(t, destAddr),
	}
	resp, err := dut.posixServer.SendTo(ctx, &req)
	if err != nil {
		t.Fatalf("faled to call SendTo: %s", err)
	}
	return resp.GetRet(), syscall.Errno(resp.GetErrno_())
}

// SetNonBlocking will set O_NONBLOCK flag for fd if nonblocking
// is true, otherwise it will clear the flag.
func (dut *DUT) SetNonBlocking(t *testing.T, fd int32, nonblocking bool) {
	t.Helper()

	flags := dut.Fcntl(t, fd, unix.F_GETFL, 0)
	if nonblocking {
		flags |= unix.O_NONBLOCK
	} else {
		flags &= ^unix.O_NONBLOCK
	}
	dut.Fcntl(t, fd, unix.F_SETFL, flags)
}

func (dut *DUT) setSockOpt(ctx context.Context, t *testing.T, sockfd, level, optname int32, optval *pb.SockOptVal) (int32, error) {
	t.Helper()

	req := pb.SetSockOptRequest{
		Sockfd:  sockfd,
		Level:   level,
		Optname: optname,
		Optval:  optval,
	}
	resp, err := dut.posixServer.SetSockOpt(ctx, &req)
	if err != nil {
		t.Fatalf("failed to call SetSockOpt: %s", err)
	}
	return resp.GetRet(), syscall.Errno(resp.GetErrno_())
}

// SetSockOpt calls setsockopt on the DUT and causes a fatal test failure if it
// doesn't succeed. If more control over the timeout or error handling is
// needed, use SetSockOptWithErrno. Because endianess and the width of values
// might differ between the testbench and DUT architectures, prefer to use a
// more specific SetSockOptXxx function.
func (dut *DUT) SetSockOpt(t *testing.T, sockfd, level, optname int32, optval []byte) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), RPCTimeout)
	defer cancel()
	ret, err := dut.SetSockOptWithErrno(ctx, t, sockfd, level, optname, optval)
	if ret != 0 {
		t.Fatalf("failed to SetSockOpt: %s", err)
	}
}

// SetSockOptWithErrno calls setsockopt on the DUT. Because endianess and the
// width of values might differ between the testbench and DUT architectures,
// prefer to use a more specific SetSockOptXxxWithErrno function.
func (dut *DUT) SetSockOptWithErrno(ctx context.Context, t *testing.T, sockfd, level, optname int32, optval []byte) (int32, error) {
	t.Helper()

	return dut.setSockOpt(ctx, t, sockfd, level, optname, &pb.SockOptVal{Val: &pb.SockOptVal_Bytesval{optval}})
}

// SetSockOptInt calls setsockopt on the DUT and causes a fatal test failure
// if it doesn't succeed. If more control over the int optval or error handling
// is needed, use SetSockOptIntWithErrno.
func (dut *DUT) SetSockOptInt(t *testing.T, sockfd, level, optname, optval int32) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), RPCTimeout)
	defer cancel()
	ret, err := dut.SetSockOptIntWithErrno(ctx, t, sockfd, level, optname, optval)
	if ret != 0 {
		t.Fatalf("failed to SetSockOptInt: %s", err)
	}
}

// SetSockOptIntWithErrno calls setsockopt with an integer optval.
func (dut *DUT) SetSockOptIntWithErrno(ctx context.Context, t *testing.T, sockfd, level, optname, optval int32) (int32, error) {
	t.Helper()

	return dut.setSockOpt(ctx, t, sockfd, level, optname, &pb.SockOptVal{Val: &pb.SockOptVal_Intval{optval}})
}

// SetSockOptTimeval calls setsockopt on the DUT and causes a fatal test failure
// if it doesn't succeed. If more control over the timeout or error handling is
// needed, use SetSockOptTimevalWithErrno.
func (dut *DUT) SetSockOptTimeval(t *testing.T, sockfd, level, optname int32, tv *unix.Timeval) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), RPCTimeout)
	defer cancel()
	ret, err := dut.SetSockOptTimevalWithErrno(ctx, t, sockfd, level, optname, tv)
	if ret != 0 {
		t.Fatalf("failed to SetSockOptTimeval: %s", err)
	}
}

// SetSockOptTimevalWithErrno calls setsockopt with the timeval converted to
// bytes.
func (dut *DUT) SetSockOptTimevalWithErrno(ctx context.Context, t *testing.T, sockfd, level, optname int32, tv *unix.Timeval) (int32, error) {
	t.Helper()

	timeval := pb.Timeval{
		Seconds:      int64(tv.Sec),
		Microseconds: int64(tv.Usec),
	}
	return dut.setSockOpt(ctx, t, sockfd, level, optname, &pb.SockOptVal{Val: &pb.SockOptVal_Timeval{&timeval}})
}

// Socket calls socket on the DUT and returns the file descriptor. If socket
// fails on the DUT, the test ends.
func (dut *DUT) Socket(t *testing.T, domain, typ, proto int32) int32 {
	t.Helper()

	fd, err := dut.SocketWithErrno(t, domain, typ, proto)
	if fd < 0 {
		t.Fatalf("failed to create socket: %s", err)
	}
	return fd
}

// SocketWithErrno calls socket on the DUT and returns the fd and errno.
func (dut *DUT) SocketWithErrno(t *testing.T, domain, typ, proto int32) (int32, error) {
	t.Helper()

	req := pb.SocketRequest{
		Domain:   domain,
		Type:     typ,
		Protocol: proto,
	}
	ctx := context.Background()
	resp, err := dut.posixServer.Socket(ctx, &req)
	if err != nil {
		t.Fatalf("failed to call Socket: %s", err)
	}
	return resp.GetFd(), syscall.Errno(resp.GetErrno_())
}

// Recv calls recv on the DUT and causes a fatal test failure if it doesn't
// succeed. If more control over the timeout or error handling is needed, use
// RecvWithErrno.
func (dut *DUT) Recv(t *testing.T, sockfd, len, flags int32) []byte {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), RPCTimeout)
	defer cancel()
	ret, buf, err := dut.RecvWithErrno(ctx, t, sockfd, len, flags)
	if ret == -1 {
		t.Fatalf("failed to recv: %s", err)
	}
	return buf
}

// RecvWithErrno calls recv on the DUT.
func (dut *DUT) RecvWithErrno(ctx context.Context, t *testing.T, sockfd, len, flags int32) (int32, []byte, error) {
	t.Helper()

	req := pb.RecvRequest{
		Sockfd: sockfd,
		Len:    len,
		Flags:  flags,
	}
	resp, err := dut.posixServer.Recv(ctx, &req)
	if err != nil {
		t.Fatalf("failed to call Recv: %s", err)
	}
	return resp.GetRet(), resp.GetBuf(), syscall.Errno(resp.GetErrno_())
}

// SetSockLingerOption sets SO_LINGER socket option on the DUT.
func (dut *DUT) SetSockLingerOption(t *testing.T, sockfd int32, timeout time.Duration, enable bool) {
	var linger unix.Linger
	if enable {
		linger.Onoff = 1
	}
	linger.Linger = int32(timeout / time.Second)

	buf := make([]byte, 8)
	binary.LittleEndian.PutUint32(buf, uint32(linger.Onoff))
	binary.LittleEndian.PutUint32(buf[4:], uint32(linger.Linger))
	dut.SetSockOpt(t, sockfd, unix.SOL_SOCKET, unix.SO_LINGER, buf)
}

// Shutdown calls shutdown on the DUT and causes a fatal test failure if it doesn't
// succeed. If more control over the timeout or error handling is needed, use
// ShutdownWithErrno.
func (dut *DUT) Shutdown(t *testing.T, fd, how int32) error {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), RPCTimeout)
	defer cancel()
	return dut.ShutdownWithErrno(ctx, t, fd, how)
}

// ShutdownWithErrno calls shutdown on the DUT.
func (dut *DUT) ShutdownWithErrno(ctx context.Context, t *testing.T, fd, how int32) error {
	t.Helper()

	req := pb.ShutdownRequest{
		Fd:  fd,
		How: how,
	}
	resp, err := dut.posixServer.Shutdown(ctx, &req)
	if err != nil {
		t.Fatalf("failed to call Shutdown: %s", err)
	}
	return syscall.Errno(resp.GetErrno_())
}
