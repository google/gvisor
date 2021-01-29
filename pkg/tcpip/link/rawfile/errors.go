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

// +build linux

package rawfile

import (
	"syscall"

	"gvisor.dev/gvisor/pkg/tcpip"
)

const maxErrno = 134

// TranslateErrno translate an errno from the syscall package into a
// tcpip.Error.
//
// Valid, but unrecognized errnos will be translated to
// *tcpip.ErrInvalidEndpointState (EINVAL).
func TranslateErrno(e syscall.Errno) tcpip.Error {
	switch e {
	case syscall.EEXIST:
		return &tcpip.ErrDuplicateAddress{}
	case syscall.ENETUNREACH:
		return &tcpip.ErrNoRoute{}
	case syscall.EINVAL:
		return &tcpip.ErrInvalidEndpointState{}
	case syscall.EALREADY:
		return &tcpip.ErrAlreadyConnecting{}
	case syscall.EISCONN:
		return &tcpip.ErrAlreadyConnected{}
	case syscall.EADDRINUSE:
		return &tcpip.ErrPortInUse{}
	case syscall.EADDRNOTAVAIL:
		return &tcpip.ErrBadLocalAddress{}
	case syscall.EPIPE:
		return &tcpip.ErrClosedForSend{}
	case syscall.EWOULDBLOCK:
		return &tcpip.ErrWouldBlock{}
	case syscall.ECONNREFUSED:
		return &tcpip.ErrConnectionRefused{}
	case syscall.ETIMEDOUT:
		return &tcpip.ErrTimeout{}
	case syscall.EINPROGRESS:
		return &tcpip.ErrConnectStarted{}
	case syscall.EDESTADDRREQ:
		return &tcpip.ErrDestinationRequired{}
	case syscall.ENOTSUP:
		return &tcpip.ErrNotSupported{}
	case syscall.ENOTTY:
		return &tcpip.ErrQueueSizeNotSupported{}
	case syscall.ENOTCONN:
		return &tcpip.ErrNotConnected{}
	case syscall.ECONNRESET:
		return &tcpip.ErrConnectionReset{}
	case syscall.ECONNABORTED:
		return &tcpip.ErrConnectionAborted{}
	case syscall.EMSGSIZE:
		return &tcpip.ErrMessageTooLong{}
	case syscall.ENOBUFS:
		return &tcpip.ErrNoBufferSpace{}
	default:
		return &tcpip.ErrInvalidEndpointState{}
	}
}
