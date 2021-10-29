// Copyright 2021 The gVisor Authors.
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

package tcpip

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux/errno"
	"gvisor.dev/gvisor/pkg/syserr"
)

// Mapping for tcpip.Error types.
var (
	SyserrUnknownProtocol       = syserr.New("unknown protocol", errno.EINVAL)
	SyserrUnknownNICID          = syserr.New("unknown nic id", errno.ENODEV)
	SyserrUnknownDevice         = syserr.New("unknown device", errno.ENODEV)
	SyserrUnknownProtocolOption = syserr.New("unknown option for protocol", errno.ENOPROTOOPT)
	SyserrDuplicateNICID        = syserr.New("duplicate nic id", errno.EEXIST)
	SyserrDuplicateAddress      = syserr.New("duplicate address", errno.EEXIST)
	SyserrAlreadyBound          = syserr.New("endpoint already bound", errno.EINVAL)
	SyserrInvalidEndpointState  = syserr.New("endpoint is in invalid state", errno.EINVAL)
	SyserrAlreadyConnecting     = syserr.New("endpoint is already connecting", errno.EALREADY)
	SyserrNoPortAvailable       = syserr.New("no ports are available", errno.EAGAIN)
	SyserrPortInUse             = syserr.New("port is in use", errno.EADDRINUSE)
	SyserrBadLocalAddress       = syserr.New("bad local address", errno.EADDRNOTAVAIL)
	SyserrClosedForSend         = syserr.New("endpoint is closed for send", errno.EPIPE)
	SyserrClosedForReceive      = syserr.New("endpoint is closed for receive", errno.NOERRNO)
	SyserrTimeout               = syserr.New("operation timed out", errno.ETIMEDOUT)
	SyserrAborted               = syserr.New("operation aborted", errno.EPIPE)
	SyserrConnectStarted        = syserr.New("connection attempt started", errno.EINPROGRESS)
	SyserrDestinationRequired   = syserr.New("destination address is required", errno.EDESTADDRREQ)
	SyserrNotSupported          = syserr.New("operation not supported", errno.EOPNOTSUPP)
	SyserrQueueSizeNotSupported = syserr.New("queue size querying not supported", errno.ENOTTY)
	SyserrNoSuchFile            = syserr.New("no such file", errno.ENOENT)
	SyserrInvalidOptionValue    = syserr.New("invalid option value specified", errno.EINVAL)
	SyserrBroadcastDisabled     = syserr.New("broadcast socket option disabled", errno.EACCES)
	SyserrNotPermittedNet       = syserr.New("operation not permitted", errno.EPERM)
	SyserrBadBuffer             = syserr.New("bad buffer", errno.EFAULT)
	SyserrMalformedHeader       = syserr.New("header is malformed", errno.EINVAL)
	SyserrInvalidPortRange      = syserr.New("invalid port range", errno.EINVAL)
)

// Error represents an error in the netstack error space.
//
// The error interface is intentionally omitted to avoid loss of type
// information that would occur if these errors were passed as error.
type Error interface {
	isError()

	// IgnoreStats indicates whether this error should be included in failure
	// counts in tcpip.Stats structs.
	IgnoreStats() bool

	fmt.Stringer

	// Translates an Error into its syserr.Error equivalent.
	translate() *syserr.Error
}

// ErrorImpl implements Error.
//
// +stateify savable
type ErrorImpl struct {
	ignoreStats bool
	sysErr      *syserr.Error
}

func (n *ErrorImpl) isError() {}

// IgnoreStats implements Error.IgnoreStats.
func (n *ErrorImpl) IgnoreStats() bool {
	return n.ignoreStats
}

// String implements String() for ErrorImpl.
func (n *ErrorImpl) String() string {
	return n.sysErr.String()
}

// Equal implements Equal() for ErrorImpl.
func (n *ErrorImpl) Equal(other *ErrorImpl) bool {
	return n == other
}

// translate returns the underlying syserr.Error.
func (n *ErrorImpl) translate() *syserr.Error {
	if n != nil {
		return n.sysErr
	}
	panic(fmt.Sprintf("this shouldn't happen: %v %T", n, n))
}

func newErrorImpl(ignoreStats bool, sysErr *syserr.Error) *ErrorImpl {
	return &ErrorImpl{
		ignoreStats: ignoreStats,
		sysErr:      sysErr,
	}
}

var (
	nilErr *ErrorImpl

	// ErrAborted indicates the operation was aborted.
	ErrAborted = newErrorImpl(false, SyserrAborted)

	// ErrAddressFamilyNotSupported indicates the operation does not support the
	// given address family.
	ErrAddressFamilyNotSupported = newErrorImpl(false, syserr.ErrAddressFamilyNotSupported)

	// ErrAlreadyBound indicates the endpoint is already bound.
	ErrAlreadyBound = newErrorImpl(true, SyserrAlreadyBound)

	// ErrAlreadyConnected indicates the endpoint is already connected.
	ErrAlreadyConnected = newErrorImpl(true, syserr.ErrAlreadyConnected)

	// ErrAlreadyConnecting indicates the endpoint is already connecting.
	ErrAlreadyConnecting = newErrorImpl(true, SyserrAlreadyConnecting)

	// ErrBadAddress indicates a bad address was provided.
	ErrBadAddress = newErrorImpl(false, syserr.ErrBadAddress)

	// ErrBadBuffer indicates a bad buffer was provided.
	ErrBadBuffer = newErrorImpl(false, SyserrBadBuffer)

	// ErrBadLocalAddress indicates a bad local address was provided.
	ErrBadLocalAddress = newErrorImpl(false, SyserrBadLocalAddress)

	// ErrBroadcastDisabled indicates broadcast is not enabled on the endpoint.
	ErrBroadcastDisabled = newErrorImpl(false, SyserrBroadcastDisabled)

	// ErrClosedForReceive indicates the endpoint is closed for incoming data.
	ErrClosedForReceive = newErrorImpl(false, SyserrClosedForReceive)

	// ErrClosedForSend indicates the endpoint is closed for outgoing data.
	ErrClosedForSend = newErrorImpl(false, SyserrClosedForSend)

	// ErrConnectStarted indicates the endpoint is connecting asynchronously.
	ErrConnectStarted = newErrorImpl(true, SyserrConnectStarted)

	// ErrConnectionAborted indicates the connection was aborted.
	ErrConnectionAborted = newErrorImpl(false, syserr.ErrConnectionAborted)

	// ErrConnectionRefused indicates the connection was refused.
	ErrConnectionRefused = newErrorImpl(false, syserr.ErrConnectionRefused)

	// ErrConnectionReset indicates the connection was reset.
	ErrConnectionReset = newErrorImpl(false, syserr.ErrConnectionReset)

	// ErrDestinationRequired indicates the operation requires a destination
	ErrDestinationRequired = newErrorImpl(false, SyserrDestinationRequired)

	// ErrDuplicateAddress indicates the operation encountered a duplicate address.
	ErrDuplicateAddress = newErrorImpl(false, SyserrDuplicateAddress)

	// ErrDuplicateNICID indicates the operation encountered a duplicate NIC ID.
	ErrDuplicateNICID = newErrorImpl(false, SyserrDuplicateNICID)

	// ErrInvalidEndpointState indicates the endpoint is in an invalid state.
	ErrInvalidEndpointState = newErrorImpl(false, SyserrInvalidEndpointState)

	// ErrInvalidOptionValue indicates an invalid option value was provided.
	ErrInvalidOptionValue = newErrorImpl(false, SyserrInvalidOptionValue)

	// ErrInvalidPortRange indicates an attempt to set an invalid port range.
	ErrInvalidPortRange = newErrorImpl(true, SyserrInvalidPortRange)

	// ErrMalformedHeader indicates the operation encountered a malformed header.
	ErrMalformedHeader = newErrorImpl(false, SyserrMalformedHeader)

	// ErrMessageTooLong indicates the operation encountered a message whose length
	ErrMessageTooLong = newErrorImpl(false, syserr.ErrMessageTooLong)

	// ErrNetworkUnreachable indicates the operation is not able to reach the
	ErrNetworkUnreachable = newErrorImpl(false, syserr.ErrNetworkUnreachable)

	// ErrNoBufferSpace indicates no buffer space is available.
	ErrNoBufferSpace = newErrorImpl(false, syserr.ErrNoBufferSpace)

	// ErrNoPortAvailable indicates no port could be allocated for the operation.
	ErrNoPortAvailable = newErrorImpl(false, SyserrNoPortAvailable)

	// ErrNoRoute indicates the operation is not able to find a route to the
	// destination.
	ErrNoRoute = newErrorImpl(false, syserr.ErrNoRoute)

	// ErrNoSuchFile is used to indicate that ENOENT should be returned the to
	ErrNoSuchFile = newErrorImpl(false, SyserrNoSuchFile)

	// ErrNotConnected indicates the endpoint is not connected.
	ErrNotConnected = newErrorImpl(false, syserr.ErrNotConnected)

	// ErrNotPermitted indicates the operation is not permitted.
	ErrNotPermitted = newErrorImpl(false, SyserrNotPermittedNet)

	// ErrNotSupported indicates the operation is not supported.
	ErrNotSupported = newErrorImpl(false, SyserrNotSupported)

	// ErrPortInUse indicates the provided port is in use.
	ErrPortInUse = newErrorImpl(false, SyserrPortInUse)

	// ErrQueueSizeNotSupported indicates the endpoint does not allow queue size
	ErrQueueSizeNotSupported = newErrorImpl(false, SyserrQueueSizeNotSupported)

	// ErrTimeout indicates the operation timed out.
	ErrTimeout = newErrorImpl(false, SyserrTimeout)

	// ErrUnknownDevice indicates an unknown device identifier was provided.
	ErrUnknownDevice = newErrorImpl(false, SyserrUnknownDevice)

	// ErrUnknownNICID indicates an unknown NIC ID was provided.
	ErrUnknownNICID = newErrorImpl(false, SyserrUnknownNICID)

	// ErrUnknownProtocol indicates an unknown protocol was requested.
	ErrUnknownProtocol = newErrorImpl(false, SyserrUnknownProtocol)

	// ErrUnknownProtocolOption indicates an unknown protocol option was provided.
	ErrUnknownProtocolOption = newErrorImpl(false, SyserrUnknownProtocolOption)

	// ErrWouldBlock indicates the operation would block.
	ErrWouldBlock = newErrorImpl(true, syserr.ErrWouldBlock)
)

// TranslateNetstackError converts an error from the tcpip package to a sentry
// internal error.
func TranslateNetstackError(err Error) *syserr.Error {
	if err != nil && err != nilErr {
		return err.translate()
	}
	return nil
}
