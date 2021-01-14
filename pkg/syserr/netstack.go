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

package syserr

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/tcpip"
)

// Mapping for tcpip.Error types.
var (
	ErrUnknownProtocol       = New(tcpip.ErrUnknownProtocol.String(), linux.EINVAL)
	ErrUnknownNICID          = New(tcpip.ErrUnknownNICID.String(), linux.ENODEV)
	ErrUnknownDevice         = New(tcpip.ErrUnknownDevice.String(), linux.ENODEV)
	ErrUnknownProtocolOption = New(tcpip.ErrUnknownProtocolOption.String(), linux.ENOPROTOOPT)
	ErrDuplicateNICID        = New(tcpip.ErrDuplicateNICID.String(), linux.EEXIST)
	ErrDuplicateAddress      = New(tcpip.ErrDuplicateAddress.String(), linux.EEXIST)
	ErrBadLinkEndpoint       = New(tcpip.ErrBadLinkEndpoint.String(), linux.EINVAL)
	ErrAlreadyBound          = New(tcpip.ErrAlreadyBound.String(), linux.EINVAL)
	ErrInvalidEndpointState  = New(tcpip.ErrInvalidEndpointState.String(), linux.EINVAL)
	ErrAlreadyConnecting     = New(tcpip.ErrAlreadyConnecting.String(), linux.EALREADY)
	ErrNoPortAvailable       = New(tcpip.ErrNoPortAvailable.String(), linux.EAGAIN)
	ErrPortInUse             = New(tcpip.ErrPortInUse.String(), linux.EADDRINUSE)
	ErrBadLocalAddress       = New(tcpip.ErrBadLocalAddress.String(), linux.EADDRNOTAVAIL)
	ErrClosedForSend         = New(tcpip.ErrClosedForSend.String(), linux.EPIPE)
	ErrClosedForReceive      = New(tcpip.ErrClosedForReceive.String(), nil)
	ErrTimeout               = New(tcpip.ErrTimeout.String(), linux.ETIMEDOUT)
	ErrAborted               = New(tcpip.ErrAborted.String(), linux.EPIPE)
	ErrConnectStarted        = New(tcpip.ErrConnectStarted.String(), linux.EINPROGRESS)
	ErrDestinationRequired   = New(tcpip.ErrDestinationRequired.String(), linux.EDESTADDRREQ)
	ErrNotSupported          = New(tcpip.ErrNotSupported.String(), linux.EOPNOTSUPP)
	ErrQueueSizeNotSupported = New(tcpip.ErrQueueSizeNotSupported.String(), linux.ENOTTY)
	ErrNoSuchFile            = New(tcpip.ErrNoSuchFile.String(), linux.ENOENT)
	ErrInvalidOptionValue    = New(tcpip.ErrInvalidOptionValue.String(), linux.EINVAL)
	ErrBroadcastDisabled     = New(tcpip.ErrBroadcastDisabled.String(), linux.EACCES)
	ErrNotPermittedNet       = New(tcpip.ErrNotPermitted.String(), linux.EPERM)
	ErrBadBuffer             = New(tcpip.ErrBadBuffer.String(), linux.EFAULT)
)

var netstackErrorTranslations map[string]*Error

func addErrMapping(tcpipErr *tcpip.Error, netstackErr *Error) {
	key := tcpipErr.String()
	if _, ok := netstackErrorTranslations[key]; ok {
		panic(fmt.Sprintf("duplicate error key: %s", key))
	}
	netstackErrorTranslations[key] = netstackErr
}

func init() {
	netstackErrorTranslations = make(map[string]*Error)
	addErrMapping(tcpip.ErrUnknownProtocol, ErrUnknownProtocol)
	addErrMapping(tcpip.ErrUnknownNICID, ErrUnknownNICID)
	addErrMapping(tcpip.ErrUnknownDevice, ErrUnknownDevice)
	addErrMapping(tcpip.ErrUnknownProtocolOption, ErrUnknownProtocolOption)
	addErrMapping(tcpip.ErrDuplicateNICID, ErrDuplicateNICID)
	addErrMapping(tcpip.ErrDuplicateAddress, ErrDuplicateAddress)
	addErrMapping(tcpip.ErrNoRoute, ErrNoRoute)
	addErrMapping(tcpip.ErrBadLinkEndpoint, ErrBadLinkEndpoint)
	addErrMapping(tcpip.ErrAlreadyBound, ErrAlreadyBound)
	addErrMapping(tcpip.ErrInvalidEndpointState, ErrInvalidEndpointState)
	addErrMapping(tcpip.ErrAlreadyConnecting, ErrAlreadyConnecting)
	addErrMapping(tcpip.ErrAlreadyConnected, ErrAlreadyConnected)
	addErrMapping(tcpip.ErrNoPortAvailable, ErrNoPortAvailable)
	addErrMapping(tcpip.ErrPortInUse, ErrPortInUse)
	addErrMapping(tcpip.ErrBadLocalAddress, ErrBadLocalAddress)
	addErrMapping(tcpip.ErrClosedForSend, ErrClosedForSend)
	addErrMapping(tcpip.ErrClosedForReceive, ErrClosedForReceive)
	addErrMapping(tcpip.ErrWouldBlock, ErrWouldBlock)
	addErrMapping(tcpip.ErrConnectionRefused, ErrConnectionRefused)
	addErrMapping(tcpip.ErrTimeout, ErrTimeout)
	addErrMapping(tcpip.ErrAborted, ErrAborted)
	addErrMapping(tcpip.ErrConnectStarted, ErrConnectStarted)
	addErrMapping(tcpip.ErrDestinationRequired, ErrDestinationRequired)
	addErrMapping(tcpip.ErrNotSupported, ErrNotSupported)
	addErrMapping(tcpip.ErrQueueSizeNotSupported, ErrQueueSizeNotSupported)
	addErrMapping(tcpip.ErrNotConnected, ErrNotConnected)
	addErrMapping(tcpip.ErrConnectionReset, ErrConnectionReset)
	addErrMapping(tcpip.ErrConnectionAborted, ErrConnectionAborted)
	addErrMapping(tcpip.ErrNoSuchFile, ErrNoSuchFile)
	addErrMapping(tcpip.ErrInvalidOptionValue, ErrInvalidOptionValue)
	addErrMapping(tcpip.ErrBadAddress, ErrBadAddress)
	addErrMapping(tcpip.ErrNetworkUnreachable, ErrNetworkUnreachable)
	addErrMapping(tcpip.ErrMessageTooLong, ErrMessageTooLong)
	addErrMapping(tcpip.ErrNoBufferSpace, ErrNoBufferSpace)
	addErrMapping(tcpip.ErrBroadcastDisabled, ErrBroadcastDisabled)
	addErrMapping(tcpip.ErrNotPermitted, ErrNotPermittedNet)
	addErrMapping(tcpip.ErrAddressFamilyNotSupported, ErrAddressFamilyNotSupported)
	addErrMapping(tcpip.ErrBadBuffer, ErrBadBuffer)
}

// TranslateNetstackError converts an error from the tcpip package to a sentry
// internal error.
func TranslateNetstackError(err *tcpip.Error) *Error {
	if err == nil {
		return nil
	}
	se, ok := netstackErrorTranslations[err.String()]
	if !ok {
		panic("Unknown error: " + err.String())
	}
	return se
}
