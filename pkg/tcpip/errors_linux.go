// Copyright 2024 The gVisor Authors.
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

package tcpip

import (
	"golang.org/x/sys/unix"
)

// TranslateErrno translate an errno from the syscall package into a
// tcpip Error.
//
// Valid, but unrecognized errnos will be translated to
// *ErrInvalidEndpointState (EINVAL). This includes the "zero" value.
func TranslateErrno(e unix.Errno) Error {
	switch e {
	case unix.EEXIST:
		return &ErrDuplicateAddress{}
	case unix.ENETUNREACH:
		return &ErrHostUnreachable{}
	case unix.EINVAL:
		return &ErrInvalidEndpointState{}
	case unix.EALREADY:
		return &ErrAlreadyConnecting{}
	case unix.EISCONN:
		return &ErrAlreadyConnected{}
	case unix.EADDRINUSE:
		return &ErrPortInUse{}
	case unix.EADDRNOTAVAIL:
		return &ErrBadLocalAddress{}
	case unix.EPIPE:
		return &ErrClosedForSend{}
	case unix.EWOULDBLOCK:
		return &ErrWouldBlock{}
	case unix.ECONNREFUSED:
		return &ErrConnectionRefused{}
	case unix.ETIMEDOUT:
		return &ErrTimeout{}
	case unix.EINPROGRESS:
		return &ErrConnectStarted{}
	case unix.EDESTADDRREQ:
		return &ErrDestinationRequired{}
	case unix.ENOTSUP:
		return &ErrNotSupported{}
	case unix.ENOTTY:
		return &ErrQueueSizeNotSupported{}
	case unix.ENOTCONN:
		return &ErrNotConnected{}
	case unix.ECONNRESET:
		return &ErrConnectionReset{}
	case unix.ECONNABORTED:
		return &ErrConnectionAborted{}
	case unix.EMSGSIZE:
		return &ErrMessageTooLong{}
	case unix.ENOBUFS:
		return &ErrNoBufferSpace{}
	default:
		return &ErrInvalidEndpointState{}
	}
}
