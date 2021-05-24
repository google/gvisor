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

// LINT.IfChange

// Mapping for tcpip.Error types.
var (
	ErrUnknownProtocol       = New((&tcpip.ErrUnknownProtocol{}).String(), linux.EINVAL)
	ErrUnknownNICID          = New((&tcpip.ErrUnknownNICID{}).String(), linux.ENODEV)
	ErrUnknownDevice         = New((&tcpip.ErrUnknownDevice{}).String(), linux.ENODEV)
	ErrUnknownProtocolOption = New((&tcpip.ErrUnknownProtocolOption{}).String(), linux.ENOPROTOOPT)
	ErrDuplicateNICID        = New((&tcpip.ErrDuplicateNICID{}).String(), linux.EEXIST)
	ErrDuplicateAddress      = New((&tcpip.ErrDuplicateAddress{}).String(), linux.EEXIST)
	ErrAlreadyBound          = New((&tcpip.ErrAlreadyBound{}).String(), linux.EINVAL)
	ErrInvalidEndpointState  = New((&tcpip.ErrInvalidEndpointState{}).String(), linux.EINVAL)
	ErrAlreadyConnecting     = New((&tcpip.ErrAlreadyConnecting{}).String(), linux.EALREADY)
	ErrNoPortAvailable       = New((&tcpip.ErrNoPortAvailable{}).String(), linux.EAGAIN)
	ErrPortInUse             = New((&tcpip.ErrPortInUse{}).String(), linux.EADDRINUSE)
	ErrBadLocalAddress       = New((&tcpip.ErrBadLocalAddress{}).String(), linux.EADDRNOTAVAIL)
	ErrClosedForSend         = New((&tcpip.ErrClosedForSend{}).String(), linux.EPIPE)
	ErrClosedForReceive      = New((&tcpip.ErrClosedForReceive{}).String(), linux.NOERRNO)
	ErrTimeout               = New((&tcpip.ErrTimeout{}).String(), linux.ETIMEDOUT)
	ErrAborted               = New((&tcpip.ErrAborted{}).String(), linux.EPIPE)
	ErrConnectStarted        = New((&tcpip.ErrConnectStarted{}).String(), linux.EINPROGRESS)
	ErrDestinationRequired   = New((&tcpip.ErrDestinationRequired{}).String(), linux.EDESTADDRREQ)
	ErrNotSupported          = New((&tcpip.ErrNotSupported{}).String(), linux.EOPNOTSUPP)
	ErrQueueSizeNotSupported = New((&tcpip.ErrQueueSizeNotSupported{}).String(), linux.ENOTTY)
	ErrNoSuchFile            = New((&tcpip.ErrNoSuchFile{}).String(), linux.ENOENT)
	ErrInvalidOptionValue    = New((&tcpip.ErrInvalidOptionValue{}).String(), linux.EINVAL)
	ErrBroadcastDisabled     = New((&tcpip.ErrBroadcastDisabled{}).String(), linux.EACCES)
	ErrNotPermittedNet       = New((&tcpip.ErrNotPermitted{}).String(), linux.EPERM)
	ErrBadBuffer             = New((&tcpip.ErrBadBuffer{}).String(), linux.EFAULT)
	ErrMalformedHeader       = New((&tcpip.ErrMalformedHeader{}).String(), linux.EINVAL)
	ErrInvalidPortRange      = New((&tcpip.ErrInvalidPortRange{}).String(), linux.EINVAL)
	ErrDuplicateRoute        = New((&tcpip.ErrDuplicateRoute{}).String(), linux.EEXIST)
	ErrInvalidGateway        = New((&tcpip.ErrInvalidGateway{}).String(), linux.EINVAL)
)

// TranslateNetstackError converts an error from the tcpip package to a sentry
// internal error.
func TranslateNetstackError(err tcpip.Error) *Error {
	switch err.(type) {
	case nil:
		return nil
	case *tcpip.ErrUnknownProtocol:
		return ErrUnknownProtocol
	case *tcpip.ErrUnknownNICID:
		return ErrUnknownNICID
	case *tcpip.ErrUnknownDevice:
		return ErrUnknownDevice
	case *tcpip.ErrUnknownProtocolOption:
		return ErrUnknownProtocolOption
	case *tcpip.ErrDuplicateNICID:
		return ErrDuplicateNICID
	case *tcpip.ErrDuplicateAddress:
		return ErrDuplicateAddress
	case *tcpip.ErrNoRoute:
		return ErrNoRoute
	case *tcpip.ErrAlreadyBound:
		return ErrAlreadyBound
	case *tcpip.ErrInvalidEndpointState:
		return ErrInvalidEndpointState
	case *tcpip.ErrAlreadyConnecting:
		return ErrAlreadyConnecting
	case *tcpip.ErrAlreadyConnected:
		return ErrAlreadyConnected
	case *tcpip.ErrNoPortAvailable:
		return ErrNoPortAvailable
	case *tcpip.ErrPortInUse:
		return ErrPortInUse
	case *tcpip.ErrBadLocalAddress:
		return ErrBadLocalAddress
	case *tcpip.ErrClosedForSend:
		return ErrClosedForSend
	case *tcpip.ErrClosedForReceive:
		return ErrClosedForReceive
	case *tcpip.ErrWouldBlock:
		return ErrWouldBlock
	case *tcpip.ErrConnectionRefused:
		return ErrConnectionRefused
	case *tcpip.ErrTimeout:
		return ErrTimeout
	case *tcpip.ErrAborted:
		return ErrAborted
	case *tcpip.ErrConnectStarted:
		return ErrConnectStarted
	case *tcpip.ErrDestinationRequired:
		return ErrDestinationRequired
	case *tcpip.ErrNotSupported:
		return ErrNotSupported
	case *tcpip.ErrQueueSizeNotSupported:
		return ErrQueueSizeNotSupported
	case *tcpip.ErrNotConnected:
		return ErrNotConnected
	case *tcpip.ErrConnectionReset:
		return ErrConnectionReset
	case *tcpip.ErrConnectionAborted:
		return ErrConnectionAborted
	case *tcpip.ErrNoSuchFile:
		return ErrNoSuchFile
	case *tcpip.ErrInvalidOptionValue:
		return ErrInvalidOptionValue
	case *tcpip.ErrBadAddress:
		return ErrBadAddress
	case *tcpip.ErrNetworkUnreachable:
		return ErrNetworkUnreachable
	case *tcpip.ErrMessageTooLong:
		return ErrMessageTooLong
	case *tcpip.ErrNoBufferSpace:
		return ErrNoBufferSpace
	case *tcpip.ErrBroadcastDisabled:
		return ErrBroadcastDisabled
	case *tcpip.ErrNotPermitted:
		return ErrNotPermittedNet
	case *tcpip.ErrAddressFamilyNotSupported:
		return ErrAddressFamilyNotSupported
	case *tcpip.ErrBadBuffer:
		return ErrBadBuffer
	case *tcpip.ErrMalformedHeader:
		return ErrMalformedHeader
	case *tcpip.ErrInvalidPortRange:
		return ErrInvalidPortRange
	case *tcpip.ErrDuplicateRoute:
		return ErrDuplicateRoute
	case *tcpip.ErrInvalidGateway:
		return ErrInvalidGateway
	default:
		panic(fmt.Sprintf("unknown error %T", err))
	}
}

// LINT.ThenChange(../tcpip/errors.go)
