// Copyright 2023 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package hostinet

import (
	"fmt"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/syserr"
)

const (
	sizeofInt16 = 2
	sizeofInt32 = 4
)

// SockOpt is used to generate get/setsockopt handlers and filters.
type SockOpt struct {
	// Level the socket option applies to.
	Level uint64
	// Name of the option.
	Name uint64
	// Size of the parameter. A size of 0 indicates that any size is
	// allowed (used for string or other variable-length types).
	Size uint64
	// Support getsockopt on this option.
	AllowGet bool
	// Support setsockopt on this option.
	AllowSet bool
}

// SockOpts are the socket options supported by hostinet by making syscalls to the host.
//
// Note the following socket options are supported but do not need syscalls to
// the host, so do not appear on this list:
//   - SO_TYPE, SO_PROTOCOL, SO_DOMAIN are handled at the syscall level in
//     syscalls/sys_socket.go.
//   - SO_SNDTIMEOU, SO_RCVTIMEO are handled internally by setting the embedded
//     socket.SendReceiveTimeout.
var SockOpts = []SockOpt{
	{linux.SOL_IP, linux.IP_ADD_MEMBERSHIP, 0, false, true},
	{linux.SOL_IP, linux.IP_DROP_MEMBERSHIP, 0, false, true},
	{linux.SOL_IP, linux.IP_HDRINCL, sizeofInt32, true, true},
	{linux.SOL_IP, linux.IP_MULTICAST_IF, 0 /* kernel allows multiple structures to be passed */, true, true},
	{linux.SOL_IP, linux.IP_MULTICAST_LOOP, 0 /* can be 32-bit int or 8-bit uint */, true, true},
	{linux.SOL_IP, linux.IP_MULTICAST_TTL, 0 /* can be 32-bit int or 8-bit uint */, true, true},
	{linux.SOL_IP, linux.IP_MTU_DISCOVER, 0 /* can be 32-bit int or 8-bit uint */, true, true},
	{linux.SOL_IP, linux.IP_PKTINFO, sizeofInt32, true, true},
	{linux.SOL_IP, linux.IP_RECVERR, sizeofInt32, true, true},
	{linux.SOL_IP, linux.IP_RECVORIGDSTADDR, sizeofInt32, true, true},
	{linux.SOL_IP, linux.IP_RECVTOS, sizeofInt32, true, true},
	{linux.SOL_IP, linux.IP_RECVTTL, sizeofInt32, true, true},
	{linux.SOL_IP, linux.IP_TOS, 0 /* Can be 32, 16, or 8 bits */, true, true},
	{linux.SOL_IP, linux.IP_TTL, sizeofInt32, true, true},

	{linux.SOL_IPV6, linux.IPV6_CHECKSUM, sizeofInt32, true, true},
	{linux.SOL_IPV6, linux.IPV6_MULTICAST_HOPS, sizeofInt32, true, true},
	{linux.SOL_IPV6, linux.IPV6_RECVERR, sizeofInt32, true, true},
	{linux.SOL_IPV6, linux.IPV6_RECVHOPLIMIT, sizeofInt32, true, true},
	{linux.SOL_IPV6, linux.IPV6_RECVORIGDSTADDR, sizeofInt32, true, true},
	{linux.SOL_IPV6, linux.IPV6_RECVPKTINFO, sizeofInt32, true, true},
	{linux.SOL_IPV6, linux.IPV6_RECVTCLASS, sizeofInt32, true, true},
	{linux.SOL_IPV6, linux.IPV6_TCLASS, sizeofInt32, true, true},
	{linux.SOL_IPV6, linux.IPV6_UNICAST_HOPS, sizeofInt32, true, true},
	{linux.SOL_IPV6, linux.IPV6_V6ONLY, sizeofInt32, true, true},

	{linux.SOL_SOCKET, linux.SO_ACCEPTCONN, sizeofInt32, true, true},
	{linux.SOL_SOCKET, linux.SO_BINDTODEVICE, 0, true, true},
	{linux.SOL_SOCKET, linux.SO_BROADCAST, sizeofInt32, true, true},
	{linux.SOL_SOCKET, linux.SO_ERROR, sizeofInt32, true, false},
	{linux.SOL_SOCKET, linux.SO_KEEPALIVE, sizeofInt32, true, true},
	{linux.SOL_SOCKET, linux.SO_LINGER, linux.SizeOfLinger, true, true},
	{linux.SOL_SOCKET, linux.SO_NO_CHECK, sizeofInt32, true, true},
	{linux.SOL_SOCKET, linux.SO_OOBINLINE, sizeofInt32, true, true},
	{linux.SOL_SOCKET, linux.SO_PASSCRED, sizeofInt32, true, true},
	{linux.SOL_SOCKET, linux.SO_RCVBUF, sizeofInt32, true, true},
	{linux.SOL_SOCKET, linux.SO_RCVBUFFORCE, sizeofInt32, false, true},
	{linux.SOL_SOCKET, linux.SO_RCVLOWAT, sizeofInt32, true, true},
	{linux.SOL_SOCKET, linux.SO_REUSEADDR, sizeofInt32, true, true},
	{linux.SOL_SOCKET, linux.SO_REUSEPORT, sizeofInt32, true, true},
	{linux.SOL_SOCKET, linux.SO_SNDBUF, sizeofInt32, true, true},
	{linux.SOL_SOCKET, linux.SO_TIMESTAMP, sizeofInt32, true, true},

	{linux.SOL_TCP, linux.TCP_CONGESTION, 0 /* string */, true, true},
	{linux.SOL_TCP, linux.TCP_CORK, sizeofInt32, true, true},
	{linux.SOL_TCP, linux.TCP_DEFER_ACCEPT, sizeofInt32, true, true},
	{linux.SOL_TCP, linux.TCP_INFO, uint64(linux.SizeOfTCPInfo), true, false},
	{linux.SOL_TCP, linux.TCP_INQ, sizeofInt32, true, true},
	{linux.SOL_TCP, linux.TCP_KEEPCNT, sizeofInt32, true, true},
	{linux.SOL_TCP, linux.TCP_KEEPIDLE, sizeofInt32, true, true},
	{linux.SOL_TCP, linux.TCP_KEEPINTVL, sizeofInt32, true, true},
	{linux.SOL_TCP, linux.TCP_LINGER2, sizeofInt32, true, true},
	{linux.SOL_TCP, linux.TCP_MAXSEG, sizeofInt32, true, true},
	{linux.SOL_TCP, linux.TCP_NODELAY, sizeofInt32, true, true},
	{linux.SOL_TCP, linux.TCP_QUICKACK, sizeofInt32, true, true},
	{linux.SOL_TCP, linux.TCP_SYNCNT, sizeofInt32, true, true},
	{linux.SOL_TCP, linux.TCP_USER_TIMEOUT, sizeofInt32, true, true},
	{linux.SOL_TCP, linux.TCP_WINDOW_CLAMP, sizeofInt32, true, true},

	{linux.SOL_ICMPV6, linux.ICMPV6_FILTER, uint64(linux.SizeOfICMP6Filter), true, true},
}

// sockOptMap is a map of {level, name} -> SockOpts. It is an optimization for
// looking up SockOpts by level and name. The map is initialized in the first
// call to Get/SetSockOpt.
var (
	sockOptMap     map[levelName]SockOpt
	sockOptMapOnce sync.Once
)

type levelName struct {
	level uint64
	name  uint64
}

func initSockOptMap(t *kernel.Task) {
	opts := append(SockOpts, extraSockOpts(t)...)
	sockOptMap = make(map[levelName]SockOpt, len(opts))
	for _, opt := range opts {
		ln := levelName{opt.Level, opt.Name}
		if _, ok := sockOptMap[ln]; ok {
			panic(fmt.Sprintf("multiple sockopts with level=%d and name=%d", opt.Level, opt.Name))
		}
		sockOptMap[ln] = opt
	}
}

// GetSockOpt implements socket.Socket.GetSockOpt.
func (s *Socket) GetSockOpt(t *kernel.Task, level, name int, optValAddr hostarch.Addr, optLen int) (marshal.Marshallable, *syserr.Error) {
	sockOptMapOnce.Do(func() { initSockOptMap(t) })

	if optLen < 0 {
		return nil, syserr.ErrInvalidArgument
	}

	// Special case send/recv timeouts since those are handled internally.
	if level == linux.SOL_SOCKET {
		switch name {
		case linux.SO_RCVTIMEO:
			recvTimeout := linux.NsecToTimeval(s.RecvTimeout())
			return &recvTimeout, nil
		case linux.SO_SNDTIMEO:
			sndTimeout := linux.NsecToTimeval(s.SendTimeout())
			return &sndTimeout, nil
		}
	}

	sockOpt, ok := sockOptMap[levelName{uint64(level), uint64(name)}]
	if !ok {
		return nil, syserr.ErrProtocolNotAvailable
	}
	if !sockOpt.AllowGet {
		return nil, syserr.ErrInvalidArgument
	}
	var opt []byte
	if sockOpt.Size > 0 {
		// Validate size of input buffer.
		if uint64(optLen) < sockOpt.Size {
			// Special case for options that allow smaller buffers.
			//
			// To keep the syscall filters simple and restrictive,
			// we use the full buffer size when calling the host,
			// but truncate before returning to the application.
			switch {
			case level == linux.SOL_TCP && name == linux.TCP_INFO:
				// Allow smaller buffer.
			case level == linux.SOL_ICMPV6 && name == linux.ICMPV6_FILTER:
				// Allow smaller buffer.
			case level == linux.SOL_IP && name == linux.IP_TTL:
				// Allow smaller buffer.
			case level == linux.SOL_IPV6 && name == linux.IPV6_TCLASS:
				// Allow smaller buffer.
			default:
				return nil, syserr.ErrInvalidArgument
			}
		}
		opt = make([]byte, sockOpt.Size)
	} else {
		// No size checking. This is probably a string. Use the size
		// they gave us.
		opt = make([]byte, optLen)
	}
	if err := preGetSockOpt(t, level, name, optValAddr, opt); err != nil {
		return nil, syserr.FromError(err)
	}
	var err error
	opt, err = getsockopt(s.fd, level, name, opt)
	if err != nil {
		return nil, syserr.FromError(err)
	}
	opt = postGetSockOpt(t, level, name, opt)
	// If option allows a smaller buffer, truncate it to desired size.
	if uint64(optLen) < sockOpt.Size {
		opt = opt[:optLen]
	}
	optP := primitive.ByteSlice(opt)
	return &optP, nil
}

// SetSockOpt implements socket.Socket.SetSockOpt.
func (s *Socket) SetSockOpt(t *kernel.Task, level, name int, opt []byte) *syserr.Error {
	sockOptMapOnce.Do(func() { initSockOptMap(t) })

	// Special case send/recv timeouts since those are handled internally.
	if level == linux.SOL_SOCKET {
		switch name {
		case linux.SO_RCVTIMEO:
			optLen := linux.SizeOfTimeval
			var v linux.Timeval
			v.UnmarshalBytes(opt[:optLen])
			if v.Usec < 0 || v.Usec >= int64(time.Second/time.Microsecond) {
				return syserr.ErrDomain
			}
			s.SetRecvTimeout(v.ToNsecCapped())
			return nil
		case linux.SO_SNDTIMEO:
			optLen := linux.SizeOfTimeval
			var v linux.Timeval
			v.UnmarshalBytes(opt[:optLen])
			if v.Usec < 0 || v.Usec >= int64(time.Second/time.Microsecond) {
				return syserr.ErrDomain
			}
			s.SetSendTimeout(v.ToNsecCapped())
			return nil
		}
	}
	sockOpt, ok := sockOptMap[levelName{uint64(level), uint64(name)}]
	if !ok {
		// Pretend to accept socket options we don't understand. This
		// seems dangerous, but it's what netstack does...
		return nil
	}
	if !sockOpt.AllowSet {
		return syserr.ErrInvalidArgument
	}
	if sockOpt.Size > 0 {
		if uint64(len(opt)) < sockOpt.Size {
			return syserr.ErrInvalidArgument
		}
		opt = opt[:sockOpt.Size]
	}
	if _, _, errno := unix.Syscall6(unix.SYS_SETSOCKOPT, uintptr(s.fd), uintptr(level), uintptr(name), uintptr(firstBytePtr(opt)), uintptr(len(opt)), 0); errno != 0 {
		return syserr.FromError(errno)
	}
	return nil
}
