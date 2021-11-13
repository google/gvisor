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

package tcpip

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux/errno"
	"gvisor.dev/gvisor/pkg/syserr"
)

// LINT.IfChange

// Mapping for tcpip.Error types.
var (
	SyserrUnknownProtocol       = syserr.New((&ErrUnknownProtocol{}).String(), errno.EINVAL)
	SyserrUnknownNICID          = syserr.New((&ErrUnknownNICID{}).String(), errno.ENODEV)
	SyserrUnknownDevice         = syserr.New((&ErrUnknownDevice{}).String(), errno.ENODEV)
	SyserrUnknownProtocolOption = syserr.New((&ErrUnknownProtocolOption{}).String(), errno.ENOPROTOOPT)
	SyserrDuplicateNICID        = syserr.New((&ErrDuplicateNICID{}).String(), errno.EEXIST)
	SyserrDuplicateAddress      = syserr.New((&ErrDuplicateAddress{}).String(), errno.EEXIST)
	SyserrAlreadyBound          = syserr.New((&ErrAlreadyBound{}).String(), errno.EINVAL)
	SyserrInvalidEndpointState  = syserr.New((&ErrInvalidEndpointState{}).String(), errno.EINVAL)
	SyserrAlreadyConnecting     = syserr.New((&ErrAlreadyConnecting{}).String(), errno.EALREADY)
	SyserrNoPortAvailable       = syserr.New((&ErrNoPortAvailable{}).String(), errno.EAGAIN)
	SyserrPortInUse             = syserr.New((&ErrPortInUse{}).String(), errno.EADDRINUSE)
	SyserrBadLocalAddress       = syserr.New((&ErrBadLocalAddress{}).String(), errno.EADDRNOTAVAIL)
	SyserrClosedForSend         = syserr.New((&ErrClosedForSend{}).String(), errno.EPIPE)
	SyserrClosedForReceive      = syserr.New((&ErrClosedForReceive{}).String(), errno.NOERRNO)
	SyserrTimeout               = syserr.New((&ErrTimeout{}).String(), errno.ETIMEDOUT)
	SyserrAborted               = syserr.New((&ErrAborted{}).String(), errno.EPIPE)
	SyserrConnectStarted        = syserr.New((&ErrConnectStarted{}).String(), errno.EINPROGRESS)
	SyserrDestinationRequired   = syserr.New((&ErrDestinationRequired{}).String(), errno.EDESTADDRREQ)
	SyserrNotSupported          = syserr.New((&ErrNotSupported{}).String(), errno.EOPNOTSUPP)
	SyserrQueueSizeNotSupported = syserr.New((&ErrQueueSizeNotSupported{}).String(), errno.ENOTTY)
	SyserrNoSuchFile            = syserr.New((&ErrNoSuchFile{}).String(), errno.ENOENT)
	SyserrInvalidOptionValue    = syserr.New((&ErrInvalidOptionValue{}).String(), errno.EINVAL)
	SyserrBroadcastDisabled     = syserr.New((&ErrBroadcastDisabled{}).String(), errno.EACCES)
	SyserrNotPermittedNet       = syserr.New((&ErrNotPermitted{}).String(), errno.EPERM)
	SyserrBadBuffer             = syserr.New((&ErrBadBuffer{}).String(), errno.EFAULT)
	SyserrMalformedHeader       = syserr.New((&ErrMalformedHeader{}).String(), errno.EINVAL)
	SyserrInvalidPortRange      = syserr.New((&ErrInvalidPortRange{}).String(), errno.EINVAL)
)

// TranslateNetstackError converts an error from the tcpip package to a sentry
// internal error.
func TranslateNetstackError(err Error) *syserr.Error {
	switch err.(type) {
	case nil:
		return nil
	case *ErrUnknownProtocol:
		return SyserrUnknownProtocol
	case *ErrUnknownNICID:
		return SyserrUnknownNICID
	case *ErrUnknownDevice:
		return SyserrUnknownDevice
	case *ErrUnknownProtocolOption:
		return SyserrUnknownProtocolOption
	case *ErrDuplicateNICID:
		return SyserrDuplicateNICID
	case *ErrDuplicateAddress:
		return SyserrDuplicateAddress
	case *ErrNoRoute:
		return syserr.ErrNoRoute
	case *ErrAlreadyBound:
		return SyserrAlreadyBound
	case *ErrInvalidEndpointState:
		return SyserrInvalidEndpointState
	case *ErrAlreadyConnecting:
		return SyserrAlreadyConnecting
	case *ErrAlreadyConnected:
		return syserr.ErrAlreadyConnected
	case *ErrNoPortAvailable:
		return SyserrNoPortAvailable
	case *ErrPortInUse:
		return SyserrPortInUse
	case *ErrBadLocalAddress:
		return SyserrBadLocalAddress
	case *ErrClosedForSend:
		return SyserrClosedForSend
	case *ErrClosedForReceive:
		return SyserrClosedForReceive
	case *ErrWouldBlock:
		return syserr.ErrWouldBlock
	case *ErrConnectionRefused:
		return syserr.ErrConnectionRefused
	case *ErrTimeout:
		return SyserrTimeout
	case *ErrAborted:
		return SyserrAborted
	case *ErrConnectStarted:
		return SyserrConnectStarted
	case *ErrDestinationRequired:
		return SyserrDestinationRequired
	case *ErrNotSupported:
		return SyserrNotSupported
	case *ErrQueueSizeNotSupported:
		return SyserrQueueSizeNotSupported
	case *ErrNotConnected:
		return syserr.ErrNotConnected
	case *ErrConnectionReset:
		return syserr.ErrConnectionReset
	case *ErrConnectionAborted:
		return syserr.ErrConnectionAborted
	case *ErrNoSuchFile:
		return SyserrNoSuchFile
	case *ErrInvalidOptionValue:
		return SyserrInvalidOptionValue
	case *ErrBadAddress:
		return syserr.ErrBadAddress
	case *ErrNetworkUnreachable:
		return syserr.ErrNetworkUnreachable
	case *ErrMessageTooLong:
		return syserr.ErrMessageTooLong
	case *ErrNoBufferSpace:
		return syserr.ErrNoBufferSpace
	case *ErrBroadcastDisabled:
		return SyserrBroadcastDisabled
	case *ErrNotPermitted:
		return SyserrNotPermittedNet
	case *ErrAddressFamilyNotSupported:
		return syserr.ErrAddressFamilyNotSupported
	case *ErrBadBuffer:
		return SyserrBadBuffer
	case *ErrMalformedHeader:
		return SyserrMalformedHeader
	case *ErrInvalidPortRange:
		return SyserrInvalidPortRange
	default:
		panic(fmt.Sprintf("unknown error %T", err))
	}
}

// LINT.ThenChange(../tcpip/errors.go)
