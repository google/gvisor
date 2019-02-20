// Copyright 2018 Google LLC
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
	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/tcpip"
)

// Mapping for tcpip.Error types.
var (
	ErrUnknownProtocol       = New(tcpip.ErrUnknownProtocol.String(), linux.EINVAL)
	ErrUnknownNICID          = New(tcpip.ErrUnknownNICID.String(), linux.EINVAL)
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
)

var netstackErrorTranslations = map[*tcpip.Error]*Error{
	tcpip.ErrUnknownProtocol:       ErrUnknownProtocol,
	tcpip.ErrUnknownNICID:          ErrUnknownNICID,
	tcpip.ErrUnknownProtocolOption: ErrUnknownProtocolOption,
	tcpip.ErrDuplicateNICID:        ErrDuplicateNICID,
	tcpip.ErrDuplicateAddress:      ErrDuplicateAddress,
	tcpip.ErrNoRoute:               ErrNoRoute,
	tcpip.ErrBadLinkEndpoint:       ErrBadLinkEndpoint,
	tcpip.ErrAlreadyBound:          ErrAlreadyBound,
	tcpip.ErrInvalidEndpointState:  ErrInvalidEndpointState,
	tcpip.ErrAlreadyConnecting:     ErrAlreadyConnecting,
	tcpip.ErrAlreadyConnected:      ErrAlreadyConnected,
	tcpip.ErrNoPortAvailable:       ErrNoPortAvailable,
	tcpip.ErrPortInUse:             ErrPortInUse,
	tcpip.ErrBadLocalAddress:       ErrBadLocalAddress,
	tcpip.ErrClosedForSend:         ErrClosedForSend,
	tcpip.ErrClosedForReceive:      ErrClosedForReceive,
	tcpip.ErrWouldBlock:            ErrWouldBlock,
	tcpip.ErrConnectionRefused:     ErrConnectionRefused,
	tcpip.ErrTimeout:               ErrTimeout,
	tcpip.ErrAborted:               ErrAborted,
	tcpip.ErrConnectStarted:        ErrConnectStarted,
	tcpip.ErrDestinationRequired:   ErrDestinationRequired,
	tcpip.ErrNotSupported:          ErrNotSupported,
	tcpip.ErrQueueSizeNotSupported: ErrQueueSizeNotSupported,
	tcpip.ErrNotConnected:          ErrNotConnected,
	tcpip.ErrConnectionReset:       ErrConnectionReset,
	tcpip.ErrConnectionAborted:     ErrConnectionAborted,
	tcpip.ErrNoSuchFile:            ErrNoSuchFile,
	tcpip.ErrInvalidOptionValue:    ErrInvalidOptionValue,
	tcpip.ErrNoLinkAddress:         ErrHostDown,
	tcpip.ErrBadAddress:            ErrBadAddress,
	tcpip.ErrNetworkUnreachable:    ErrNetworkUnreachable,
	tcpip.ErrMessageTooLong:        ErrMessageTooLong,
	tcpip.ErrNoBufferSpace:         ErrNoBufferSpace,
	tcpip.ErrBroadcastDisabled:     ErrBroadcastDisabled,
}

// TranslateNetstackError converts an error from the tcpip package to a sentry
// internal error.
func TranslateNetstackError(err *tcpip.Error) *Error {
	if err == nil {
		return nil
	}
	se, ok := netstackErrorTranslations[err]
	if !ok {
		panic("Unknown error: " + err.String())
	}
	return se
}
