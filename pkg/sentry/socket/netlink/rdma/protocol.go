// Copyright 2026 The gVisor Authors.
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

// Package rdma provides a NETLINK_RDMA socket protocol.
//
// Only RDMA_NLDEV_CMD_SYS_GET is emulated. rdma-core's fork-safety detection
// (ibv_is_fork_initialized) queries it to learn whether the host kernel does
// copy-on-fork for pinned pages; without it, providers such as EFA arm an
// abort-on-fork handler. The sentry implements copy-on-fork for pinned pages,
// so registered memory is fork-safe; report copy-on-fork as supported.
package rdma

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/socket/netlink"
	"gvisor.dev/gvisor/pkg/sentry/socket/netlink/nlmsg"
	"gvisor.dev/gvisor/pkg/syserr"
)

// Protocol implements netlink.Protocol.
//
// +stateify savable
type Protocol struct{}

var _ netlink.Protocol = (*Protocol)(nil)

// NewProtocol creates a NETLINK_RDMA netlink.Protocol.
func NewProtocol(t *kernel.Task) (netlink.Protocol, *syserr.Error) {
	return &Protocol{}, nil
}

// Protocol implements netlink.Protocol.Protocol.
func (p *Protocol) Protocol() int {
	return linux.NETLINK_RDMA
}

// CanSend implements netlink.Protocol.CanSend.
func (p *Protocol) CanSend() bool {
	return true
}

// Receive implements netlink.Protocol.Receive.
func (p *Protocol) Receive(ctx context.Context, s *netlink.Socket, buf []byte) *syserr.Error {
	return s.ProcessMessages(ctx, buf)
}

// ProcessMessage implements netlink.Protocol.ProcessMessage.
func (p *Protocol) ProcessMessage(ctx context.Context, s *netlink.Socket, msg *nlmsg.Message, ms *nlmsg.MessageSet) *syserr.Error {
	hdr := msg.Header()
	if hdr.Type != linux.RDMANLMsgType(linux.RDMA_NL_NLDEV, linux.RDMA_NLDEV_CMD_SYS_GET) {
		// All other RDMA netlink commands are unimplemented.
		return syserr.ErrNotSupported
	}
	// See drivers/infiniband/core/nldev.c:nldev_sys_get_doit().
	m := ms.AddMessage(linux.NetlinkMessageHeader{
		Type: hdr.Type,
	})
	m.PutAttr(linux.RDMA_NLDEV_SYS_ATTR_NETNS_MODE, primitive.AllocateUint8(1))
	m.PutAttr(linux.RDMA_NLDEV_SYS_ATTR_COPY_ON_FORK, primitive.AllocateUint8(1))
	return nil
}

// init registers the NETLINK_RDMA provider.
func init() {
	netlink.RegisterProvider(linux.NETLINK_RDMA, NewProtocol)
}
