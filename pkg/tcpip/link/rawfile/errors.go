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
	"fmt"
	"syscall"

	"gvisor.dev/gvisor/pkg/tcpip"
)

const maxErrno = 134

var translations [maxErrno]*tcpip.Error

// TranslateErrno translate an errno from the syscall package into a
// *tcpip.Error.
//
// Valid, but unreconigized errnos will be translated to
// tcpip.ErrInvalidEndpointState (EINVAL). Panics on invalid errnos.
func TranslateErrno(e syscall.Errno) *tcpip.Error {
	if err := translations[e]; err != nil {
		return err
	}
	return tcpip.ErrInvalidEndpointState
}

func addTranslation(host syscall.Errno, trans *tcpip.Error) {
	if translations[host] != nil {
		panic(fmt.Sprintf("duplicate translation for host errno %q (%d)", host.Error(), host))
	}
	translations[host] = trans
}

func init() {
	addTranslation(syscall.EEXIST, tcpip.ErrDuplicateAddress)
	addTranslation(syscall.ENETUNREACH, tcpip.ErrNoRoute)
	addTranslation(syscall.EINVAL, tcpip.ErrInvalidEndpointState)
	addTranslation(syscall.EALREADY, tcpip.ErrAlreadyConnecting)
	addTranslation(syscall.EISCONN, tcpip.ErrAlreadyConnected)
	addTranslation(syscall.EADDRINUSE, tcpip.ErrPortInUse)
	addTranslation(syscall.EADDRNOTAVAIL, tcpip.ErrBadLocalAddress)
	addTranslation(syscall.EPIPE, tcpip.ErrClosedForSend)
	addTranslation(syscall.EWOULDBLOCK, tcpip.ErrWouldBlock)
	addTranslation(syscall.ECONNREFUSED, tcpip.ErrConnectionRefused)
	addTranslation(syscall.ETIMEDOUT, tcpip.ErrTimeout)
	addTranslation(syscall.EINPROGRESS, tcpip.ErrConnectStarted)
	addTranslation(syscall.EDESTADDRREQ, tcpip.ErrDestinationRequired)
	addTranslation(syscall.ENOTSUP, tcpip.ErrNotSupported)
	addTranslation(syscall.ENOTTY, tcpip.ErrQueueSizeNotSupported)
	addTranslation(syscall.ENOTCONN, tcpip.ErrNotConnected)
	addTranslation(syscall.ECONNRESET, tcpip.ErrConnectionReset)
	addTranslation(syscall.ECONNABORTED, tcpip.ErrConnectionAborted)
	addTranslation(syscall.EMSGSIZE, tcpip.ErrMessageTooLong)
	addTranslation(syscall.ENOBUFS, tcpip.ErrNoBufferSpace)
}
