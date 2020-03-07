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

// Package uevent provides a NETLINK_KOBJECT_UEVENT socket protocol.
//
// NETLINK_KOBJECT_UEVENT sockets send udev-style device events. gVisor does
// not support any device events, so these sockets never send any messages.
package uevent

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/socket/netlink"
	"gvisor.dev/gvisor/pkg/syserr"
)

// Protocol implements netlink.Protocol.
//
// +stateify savable
type Protocol struct{}

var _ netlink.Protocol = (*Protocol)(nil)

// NewProtocol creates a NETLINK_KOBJECT_UEVENT netlink.Protocol.
func NewProtocol(t *kernel.Task) (netlink.Protocol, *syserr.Error) {
	return &Protocol{}, nil
}

// Protocol implements netlink.Protocol.Protocol.
func (p *Protocol) Protocol() int {
	return linux.NETLINK_KOBJECT_UEVENT
}

// CanSend implements netlink.Protocol.CanSend.
func (p *Protocol) CanSend() bool {
	return false
}

// ProcessMessage implements netlink.Protocol.ProcessMessage.
func (p *Protocol) ProcessMessage(ctx context.Context, msg *netlink.Message, ms *netlink.MessageSet) *syserr.Error {
	// Silently ignore all messages.
	return nil
}

// init registers the NETLINK_KOBJECT_UEVENT provider.
func init() {
	netlink.RegisterProvider(linux.NETLINK_KOBJECT_UEVENT, NewProtocol)
}
