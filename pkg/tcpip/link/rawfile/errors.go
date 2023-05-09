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

//go:build linux
// +build linux

package rawfile

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
)

const maxErrno = 134

// TranslateErrno translate an errno from the syscall package into a
// tcpip.Error.
//
// Valid, but unrecognized errnos will be translated to
// *tcpip.ErrInvalidEndpointState (EINVAL).
func TranslateErrno(e unix.Errno) tcpip.Error {
	switch e {
	case unix.EEXIST:
		return &tcpip.ErrDuplicateAddress{}
	case unix.ENETUNREACH:
		return &tcpip.ErrHostUnreachable{}
	case unix.EINVAL:
		return &tcpip.ErrInvalidEndpointState{}
	case unix.EALREADY:
		return &tcpip.ErrAlreadyConnecting{}
	case unix.EISCONN:
		return &tcpip.ErrAlreadyConnected{}
	case unix.EADDRINUSE:
		return &tcpip.ErrPortInUse{}
	case unix.EADDRNOTAVAIL:
		return &tcpip.ErrBadLocalAddress{}
	case unix.EPIPE:
		return &tcpip.ErrClosedForSend{}
	case unix.EWOULDBLOCK:
		return &tcpip.ErrWouldBlock{}
	case unix.ECONNREFUSED:
		return &tcpip.ErrConnectionRefused{}
	case unix.ETIMEDOUT:
		return &tcpip.ErrTimeout{}
	case unix.EINPROGRESS:
		return &tcpip.ErrConnectStarted{}
	case unix.EDESTADDRREQ:
		return &tcpip.ErrDestinationRequired{}
	case unix.ENOTSUP:
		return &tcpip.ErrNotSupported{}
	case unix.ENOTTY:
		return &tcpip.ErrQueueSizeNotSupported{}
	case unix.ENOTCONN:
		return &tcpip.ErrNotConnected{}
	case unix.ECONNRESET:
		return &tcpip.ErrConnectionReset{}
	case unix.ECONNABORTED:
		return &tcpip.ErrConnectionAborted{}
	case unix.EMSGSIZE:
		return &tcpip.ErrMessageTooLong{}
	case unix.ENOBUFS:
		return &tcpip.ErrNoBufferSpace{}
	default:
		return &tcpip.ErrInvalidEndpointState{}
	}
}
