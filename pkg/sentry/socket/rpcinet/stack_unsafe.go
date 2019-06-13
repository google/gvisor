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

package rpcinet

import (
	"syscall"
	"unsafe"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/binary"
	pb "gvisor.dev/gvisor/pkg/sentry/socket/rpcinet/syscall_rpc_go_proto"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
	"gvisor.dev/gvisor/pkg/syserr"
)

// NewNetlinkRouteRequest builds a netlink message for getting the RIB,
// the routing information base.
func newNetlinkRouteRequest(proto, seq, family int) []byte {
	rr := &syscall.NetlinkRouteRequest{}
	rr.Header.Len = uint32(syscall.NLMSG_HDRLEN + syscall.SizeofRtGenmsg)
	rr.Header.Type = uint16(proto)
	rr.Header.Flags = syscall.NLM_F_DUMP | syscall.NLM_F_REQUEST
	rr.Header.Seq = uint32(seq)
	rr.Data.Family = uint8(family)
	return netlinkRRtoWireFormat(rr)
}

func netlinkRRtoWireFormat(rr *syscall.NetlinkRouteRequest) []byte {
	b := make([]byte, rr.Header.Len)
	*(*uint32)(unsafe.Pointer(&b[0:4][0])) = rr.Header.Len
	*(*uint16)(unsafe.Pointer(&b[4:6][0])) = rr.Header.Type
	*(*uint16)(unsafe.Pointer(&b[6:8][0])) = rr.Header.Flags
	*(*uint32)(unsafe.Pointer(&b[8:12][0])) = rr.Header.Seq
	*(*uint32)(unsafe.Pointer(&b[12:16][0])) = rr.Header.Pid
	b[16] = byte(rr.Data.Family)
	return b
}

func (s *Stack) getNetlinkFd() (uint32, *syserr.Error) {
	id, c := s.rpcConn.NewRequest(pb.SyscallRequest{Args: &pb.SyscallRequest_Socket{&pb.SocketRequest{Family: int64(syscall.AF_NETLINK), Type: int64(syscall.SOCK_RAW | syscall.SOCK_NONBLOCK), Protocol: int64(syscall.NETLINK_ROUTE)}}}, false /* ignoreResult */)
	<-c

	res := s.rpcConn.Request(id).Result.(*pb.SyscallResponse_Socket).Socket.Result
	if e, ok := res.(*pb.SocketResponse_ErrorNumber); ok {
		return 0, syserr.FromHost(syscall.Errno(e.ErrorNumber))
	}
	return res.(*pb.SocketResponse_Fd).Fd, nil
}

func (s *Stack) bindNetlinkFd(fd uint32, sockaddr []byte) *syserr.Error {
	id, c := s.rpcConn.NewRequest(pb.SyscallRequest{Args: &pb.SyscallRequest_Bind{&pb.BindRequest{Fd: fd, Address: sockaddr}}}, false /* ignoreResult */)
	<-c

	if e := s.rpcConn.Request(id).Result.(*pb.SyscallResponse_Bind).Bind.ErrorNumber; e != 0 {
		return syserr.FromHost(syscall.Errno(e))
	}
	return nil
}

func (s *Stack) closeNetlinkFd(fd uint32) {
	_, _ = s.rpcConn.NewRequest(pb.SyscallRequest{Args: &pb.SyscallRequest_Close{&pb.CloseRequest{Fd: fd}}}, true /* ignoreResult */)
}

func (s *Stack) rpcSendMsg(req *pb.SyscallRequest_Sendmsg) (uint32, *syserr.Error) {
	id, c := s.rpcConn.NewRequest(pb.SyscallRequest{Args: req}, false /* ignoreResult */)
	<-c

	res := s.rpcConn.Request(id).Result.(*pb.SyscallResponse_Sendmsg).Sendmsg.Result
	if e, ok := res.(*pb.SendmsgResponse_ErrorNumber); ok {
		return 0, syserr.FromHost(syscall.Errno(e.ErrorNumber))
	}

	return res.(*pb.SendmsgResponse_Length).Length, nil
}

func (s *Stack) sendMsg(fd uint32, buf []byte, to []byte, flags int) (int, *syserr.Error) {
	// Whitelist flags.
	if flags&^(syscall.MSG_DONTWAIT|syscall.MSG_EOR|syscall.MSG_FASTOPEN|syscall.MSG_MORE|syscall.MSG_NOSIGNAL) != 0 {
		return 0, syserr.ErrInvalidArgument
	}

	req := &pb.SyscallRequest_Sendmsg{&pb.SendmsgRequest{
		Fd:          fd,
		Data:        buf,
		Address:     to,
		More:        flags&linux.MSG_MORE != 0,
		EndOfRecord: flags&linux.MSG_EOR != 0,
	}}

	n, err := s.rpcSendMsg(req)
	return int(n), err
}

func (s *Stack) rpcRecvMsg(req *pb.SyscallRequest_Recvmsg) (*pb.RecvmsgResponse_ResultPayload, *syserr.Error) {
	id, c := s.rpcConn.NewRequest(pb.SyscallRequest{Args: req}, false /* ignoreResult */)
	<-c

	res := s.rpcConn.Request(id).Result.(*pb.SyscallResponse_Recvmsg).Recvmsg.Result
	if e, ok := res.(*pb.RecvmsgResponse_ErrorNumber); ok {
		return nil, syserr.FromHost(syscall.Errno(e.ErrorNumber))
	}

	return res.(*pb.RecvmsgResponse_Payload).Payload, nil
}

func (s *Stack) recvMsg(fd, l, flags uint32) ([]byte, *syserr.Error) {
	req := &pb.SyscallRequest_Recvmsg{&pb.RecvmsgRequest{
		Fd:     fd,
		Length: l,
		Sender: false,
		Trunc:  flags&linux.MSG_TRUNC != 0,
		Peek:   flags&linux.MSG_PEEK != 0,
	}}

	res, err := s.rpcRecvMsg(req)
	if err != nil {
		return nil, err
	}
	return res.Data, nil
}

func (s *Stack) netlinkRequest(proto, family int) ([]byte, error) {
	fd, err := s.getNetlinkFd()
	if err != nil {
		return nil, err.ToError()
	}
	defer s.closeNetlinkFd(fd)

	lsa := syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	b := binary.Marshal(nil, usermem.ByteOrder, &lsa)
	if err := s.bindNetlinkFd(fd, b); err != nil {
		return nil, err.ToError()
	}

	wb := newNetlinkRouteRequest(proto, 1, family)
	_, err = s.sendMsg(fd, wb, b, 0)
	if err != nil {
		return nil, err.ToError()
	}

	var tab []byte
done:
	for {
		rb, err := s.recvMsg(fd, uint32(syscall.Getpagesize()), 0)
		nr := len(rb)
		if err != nil {
			return nil, err.ToError()
		}

		if nr < syscall.NLMSG_HDRLEN {
			return nil, syserr.ErrInvalidArgument.ToError()
		}

		tab = append(tab, rb...)
		msgs, e := syscall.ParseNetlinkMessage(rb)
		if e != nil {
			return nil, e
		}

		for _, m := range msgs {
			if m.Header.Type == syscall.NLMSG_DONE {
				break done
			}
			if m.Header.Type == syscall.NLMSG_ERROR {
				return nil, syserr.ErrInvalidArgument.ToError()
			}
		}
	}

	return tab, nil
}

// DoNetlinkRouteRequest returns routing information base, also known as RIB,
// which consists of network facility information, states and parameters.
func (s *Stack) DoNetlinkRouteRequest(req int) ([]syscall.NetlinkMessage, error) {
	data, err := s.netlinkRequest(req, syscall.AF_UNSPEC)
	if err != nil {
		return nil, err
	}
	return syscall.ParseNetlinkMessage(data)
}
