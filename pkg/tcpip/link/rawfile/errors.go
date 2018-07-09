// Copyright 2018 Google Inc.
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

	"gvisor.googlesource.com/gvisor/pkg/tcpip"
)

var translations = map[syscall.Errno]*tcpip.Error{
	syscall.EEXIST:        tcpip.ErrDuplicateAddress,
	syscall.ENETUNREACH:   tcpip.ErrNoRoute,
	syscall.EINVAL:        tcpip.ErrInvalidEndpointState,
	syscall.EALREADY:      tcpip.ErrAlreadyConnecting,
	syscall.EISCONN:       tcpip.ErrAlreadyConnected,
	syscall.EADDRINUSE:    tcpip.ErrPortInUse,
	syscall.EADDRNOTAVAIL: tcpip.ErrBadLocalAddress,
	syscall.EPIPE:         tcpip.ErrClosedForSend,
	syscall.EWOULDBLOCK:   tcpip.ErrWouldBlock,
	syscall.ECONNREFUSED:  tcpip.ErrConnectionRefused,
	syscall.ETIMEDOUT:     tcpip.ErrTimeout,
	syscall.EINPROGRESS:   tcpip.ErrConnectStarted,
	syscall.EDESTADDRREQ:  tcpip.ErrDestinationRequired,
	syscall.ENOTSUP:       tcpip.ErrNotSupported,
	syscall.ENOTTY:        tcpip.ErrQueueSizeNotSupported,
	syscall.ENOTCONN:      tcpip.ErrNotConnected,
	syscall.ECONNRESET:    tcpip.ErrConnectionReset,
	syscall.ECONNABORTED:  tcpip.ErrConnectionAborted,
}

// TranslateErrno translate an errno from the syscall package into a
// *tcpip.Error.
//
// Not all errnos are supported and this function will panic on unreconized
// errnos.
func TranslateErrno(e syscall.Errno) *tcpip.Error {
	if err, ok := translations[e]; ok {
		return err
	}
	return tcpip.ErrInvalidEndpointState
}
