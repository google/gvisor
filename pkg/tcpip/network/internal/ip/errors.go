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

package ip

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/tcpip"
)

// ForwardingError represents an error that occurred while trying to forward
// a packet.
type ForwardingError interface {
	isForwardingError()
	fmt.Stringer
}

// ErrTTLExceeded indicates that the received packet's TTL has been exceeded.
type ErrTTLExceeded struct{}

func (*ErrTTLExceeded) isForwardingError() {}

func (*ErrTTLExceeded) String() string { return "ttl exceeded" }

// ErrOutgoingDeviceNoBufferSpace indicates that the outgoing device does not
// have enough space to hold a buffer.
type ErrOutgoingDeviceNoBufferSpace struct{}

func (*ErrOutgoingDeviceNoBufferSpace) isForwardingError() {}

func (*ErrOutgoingDeviceNoBufferSpace) String() string { return "no device buffer space" }

// ErrParameterProblem indicates the received packet had a problem with an IP
// parameter.
type ErrParameterProblem struct{}

func (*ErrParameterProblem) isForwardingError() {}

func (*ErrParameterProblem) String() string { return "parameter problem" }

// ErrInitializingSourceAddress indicates the received packet had a source
// address that may only be used on the local network as part of initialization
// work.
type ErrInitializingSourceAddress struct{}

func (*ErrInitializingSourceAddress) isForwardingError() {}

func (*ErrInitializingSourceAddress) String() string { return "initializing source address" }

// ErrLinkLocalSourceAddress indicates the received packet had a link-local
// source address.
type ErrLinkLocalSourceAddress struct{}

func (*ErrLinkLocalSourceAddress) isForwardingError() {}

func (*ErrLinkLocalSourceAddress) String() string { return "link local source address" }

// ErrLinkLocalDestinationAddress indicates the received packet had a link-local
// destination address.
type ErrLinkLocalDestinationAddress struct{}

func (*ErrLinkLocalDestinationAddress) isForwardingError() {}

func (*ErrLinkLocalDestinationAddress) String() string { return "link local destination address" }

// ErrHostUnreachable indicates that the destination host could not be reached.
type ErrHostUnreachable struct{}

func (*ErrHostUnreachable) isForwardingError() {}

func (*ErrHostUnreachable) String() string { return "no route to host" }

// ErrMessageTooLong indicates the packet was too big for the outgoing MTU.
//
// +stateify savable
type ErrMessageTooLong struct{}

func (*ErrMessageTooLong) isForwardingError() {}

func (*ErrMessageTooLong) String() string { return "message too long" }

// ErrNoMulticastPendingQueueBufferSpace indicates that a multicast packet
// could not be added to the pending packet queue due to insufficient buffer
// space.
//
// +stateify savable
type ErrNoMulticastPendingQueueBufferSpace struct{}

func (*ErrNoMulticastPendingQueueBufferSpace) isForwardingError() {}

func (*ErrNoMulticastPendingQueueBufferSpace) String() string { return "no buffer space" }

// ErrUnexpectedMulticastInputInterface indicates that the interface that the
// packet arrived on did not match the routes expected input interface.
type ErrUnexpectedMulticastInputInterface struct{}

func (*ErrUnexpectedMulticastInputInterface) isForwardingError() {}

func (*ErrUnexpectedMulticastInputInterface) String() string { return "unexpected input interface" }

// ErrUnknownOutputEndpoint indicates that the output endpoint associated with
// a route could not be found.
type ErrUnknownOutputEndpoint struct{}

func (*ErrUnknownOutputEndpoint) isForwardingError() {}

func (*ErrUnknownOutputEndpoint) String() string { return "unknown endpoint" }

// ErrOther indicates the packet coould not be forwarded for a reason
// captured by the contained error.
type ErrOther struct {
	Err tcpip.Error
}

func (*ErrOther) isForwardingError() {}

func (e *ErrOther) String() string { return fmt.Sprintf("other tcpip error: %s", e.Err) }
