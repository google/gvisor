// Copyright 2019 The gVisor Authors.
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

package raw

import (
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/packet"
	"gvisor.dev/gvisor/pkg/waiter"
)

// EndpointFactory implements stack.RawFactory.
type EndpointFactory struct{}

// NewUnassociatedEndpoint implements stack.RawFactory.NewUnassociatedEndpoint.
func (EndpointFactory) NewUnassociatedEndpoint(stack *stack.Stack, netProto tcpip.NetworkProtocolNumber, transProto tcpip.TransportProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, *tcpip.Error) {
	return newEndpoint(stack, netProto, transProto, waiterQueue, false /* associated */)
}

// NewPacketEndpoint implements stack.RawFactory.NewPacketEndpoint.
func (EndpointFactory) NewPacketEndpoint(stack *stack.Stack, cooked bool, netProto tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, *tcpip.Error) {
	return packet.NewEndpoint(stack, cooked, netProto, waiterQueue)
}
