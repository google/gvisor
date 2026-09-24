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
// gVisor implements the subset of the kernel's nldev interface that
// rdma-core uses: libibverbs device discovery (RDMA_NLDEV_CMD_GET dumps and
// RDMA_NLDEV_CMD_GET_CHARDEV for "uverbs") and fork safety detection
// (RDMA_NLDEV_CMD_SYS_GET). GET_CHARDEV for any other client, including
// librdmacm's rdma_cm, fails with ENOENT exactly as Linux does when the
// corresponding kernel client is not registered.
package rdma

import (
	"encoding/hex"
	"strconv"
	"strings"

	"gvisor.dev/gvisor/pkg/abi/ib"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/rdma"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/socket/netlink"
	"gvisor.dev/gvisor/pkg/sentry/socket/netlink/nlmsg"
	"gvisor.dev/gvisor/pkg/syserr"
)

// devData is the host sysfs snapshot served over NETLINK_RDMA, or nil if
// rdmaproxy is disabled. It is written exactly once, by Init, and never
// mutated afterwards, so readers need no synchronization (see Init).
var devData *rdma.Snapshot

// Protocol implements netlink.Protocol.
//
// +stateify savable
type Protocol struct{}

var _ netlink.Protocol = (*Protocol)(nil)

// Init publishes RDMA device data to NETLINK_RDMA sockets. If it is never
// called (or called with nil), socket(AF_NETLINK, ..., NETLINK_RDMA) fails
// with EPROTONOSUPPORT, matching a host kernel without RDMA support.
//
// Preconditions: Init is called at most once, during boot, before any
// application task exists. Calling Init any later could be a data race. The
// snapshot must not be mutated after Init.
func Init(snap *rdma.Snapshot) {
	devData = snap
}

// NewProtocol creates a NETLINK_RDMA netlink.Protocol.
func NewProtocol(t *kernel.Task) (netlink.Protocol, *syserr.Error) {
	if devData == nil {
		return nil, syserr.ErrProtocolNotSupported
	}
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
//
// From drivers/infiniband/core/netlink.c:rdma_nl_rcv_msg.
func (p *Protocol) ProcessMessage(ctx context.Context, s *netlink.Socket, msg *nlmsg.Message, ms *nlmsg.MessageSet) *syserr.Error {
	hdr := msg.Header()
	if hdr.RDMANetlinkClient() != linux.RDMA_NL_NLDEV {
		log.Debugf("Netlink RDMA: unsupported client %d", hdr.RDMANetlinkClient())
		return syserr.ErrInvalidArgument
	}

	data := devData
	if data == nil {
		// Unreachable: sockets can only be created after Init publishes a
		// non-nil snapshot, which never changes afterwards. Be defensive
		// anyway.
		return syserr.ErrInvalidArgument
	}

	switch hdr.RDMANetlinkOp() {
	case linux.RDMA_NLDEV_CMD_GET:
		return p.dumpDevices(data, msg, ms)
	case linux.RDMA_NLDEV_CMD_GET_CHARDEV:
		return p.getChardev(data, msg, ms)
	case linux.RDMA_NLDEV_CMD_SYS_GET:
		return p.sysGet(msg, ms)
	default:
		// Linux returns EINVAL for ops without a registered handler.
		// rdma-core treats the NLMSG_ERROR as "netlink unavailable" and
		// falls back to sysfs discovery.
		return syserr.ErrInvalidArgument
	}
}

// dumpDevices handles RDMA_NLDEV_CMD_GET dump requests, from
// drivers/infiniband/core/nldev.c:nldev_get_dumpit.
//
// rdma-core requires DEV_INDEX, DEV_NAME, PORT_INDEX, DEV_NODE_TYPE and
// NODE_GUID in every message, and skips devices missing any of them
// (rdma-core libibverbs/ibdev_nl.c:find_sysfs_devs_nl_cb).
func (p *Protocol) dumpDevices(data *rdma.Snapshot, msg *nlmsg.Message, ms *nlmsg.MessageSet) *syserr.Error {
	hdr := msg.Header()
	// Only the dump variant is supported; the doit variant is unused by
	// rdma-core.
	if hdr.Flags&linux.NLM_F_DUMP != linux.NLM_F_DUMP {
		return syserr.ErrNotSupported
	}

	ms.Multi = true
	for i, dev := range data.Devices {
		m := ms.AddMessage(linux.NetlinkMessageHeader{
			Type: hdr.Type,
		})
		m.PutAttr(linux.RDMA_NLDEV_ATTR_DEV_INDEX, primitive.AllocateUint32(uint32(i)))
		m.PutAttrString(linux.RDMA_NLDEV_ATTR_DEV_NAME, dev.IBDev)
		m.PutAttr(linux.RDMA_NLDEV_ATTR_PORT_INDEX, primitive.AllocateUint32(uint32(len(dev.Ports))))
		m.PutAttr(linux.RDMA_NLDEV_ATTR_DEV_NODE_TYPE, primitive.AllocateUint8(parseNodeType(dev.IBAttrs["node_type"])))
		guid := parseNodeGUID(dev.IBAttrs["node_guid"])
		guidAttr := primitive.ByteSlice(guid[:])
		m.PutAttr(linux.RDMA_NLDEV_ATTR_NODE_GUID, &guidAttr)
	}
	return nil
}

// getChardev handles RDMA_NLDEV_CMD_GET_CHARDEV requests, from
// drivers/infiniband/core/nldev.c:nldev_get_chardev.
func (p *Protocol) getChardev(data *rdma.Snapshot, msg *nlmsg.Message, ms *nlmsg.MessageSet) *syserr.Error {
	attrs, ok := chardevAttrs(msg)
	if !ok {
		return syserr.ErrInvalidArgument
	}
	typAttr, ok := attrs[linux.RDMA_NLDEV_ATTR_CHARDEV_TYPE]
	if !ok {
		return syserr.ErrInvalidArgument
	}

	hdr := msg.Header()
	switch typ := typAttr.String(); typ {
	case "uverbs":
		idxAttr, ok := attrs[linux.RDMA_NLDEV_ATTR_DEV_INDEX]
		if !ok {
			// The uverbs client is per-device; Linux fails requests
			// without a device.
			return syserr.ErrInvalidArgument
		}
		idx, ok := idxAttr.Uint32()
		if !ok || int(idx) >= len(data.Devices) {
			return syserr.ErrInvalidArgument
		}
		dev := &data.Devices[idx]

		minor, ok := parseDevMinor(dev.Dev)
		if !ok {
			log.Warningf("Netlink RDMA: cannot parse dev %q of %s", dev.Dev, dev.Uverbs)
			return syserr.ErrInvalidArgument
		}

		m := ms.AddMessage(linux.NetlinkMessageHeader{Type: hdr.Type})
		m.PutAttrString(linux.RDMA_NLDEV_ATTR_CHARDEV_NAME, dev.Uverbs)
		m.PutAttr(linux.RDMA_NLDEV_ATTR_CHARDEV_ABI, primitive.AllocateUint64(parseUint64(dev.ABIVersion)))
		m.PutAttr(linux.RDMA_NLDEV_ATTR_CHARDEV, primitive.AllocateUint64(linux.HugeEncodeDev(ib.IB_UVERBS_MAJOR, minor)))
		// DriverID was inferred at collection time, which means we don't need
		// to run the sysfs scan fallback to match devices to driver IDs.
		m.PutAttr(linux.RDMA_NLDEV_ATTR_UVERBS_DRIVER_ID, primitive.AllocateUint32(dev.DriverID))
		return nil

	default:
		// Linux fails with ENOENT when no client matches the requested type.
		log.Debugf("Netlink RDMA: unsupported chardev type %q", typ)
		return syserr.ErrNoFileOrDir
	}
}

// sysGet handles RDMA_NLDEV_CMD_SYS_GET requests, from
// drivers/infiniband/core/nldev.c:nldev_sys_get_doit.
//
// RDMA pins MR pages to prevent them from being swapped out. If you fork a
// parent process that uses RDMA that then writes to a page, the parent
// receives a new copy of that page, while the child keeps the old one.
// Meanwhile, the rNIC continues to DMA into the same physical page, now in the
// child's address space. libibverbs addresses this issue with ibv_fork_init,
// but it has multiple problems (see man pages). Linux 5.9 made it so that
// DMA-pinned pages would be copied on fork, solving this issue. PR #14031
// introduces this feature in gVisor, so we return 1 to tell the sRDMA
// submodule that copy-on-fork is implemented.
func (p *Protocol) sysGet(msg *nlmsg.Message, ms *nlmsg.MessageSet) *syserr.Error {
	m := ms.AddMessage(linux.NetlinkMessageHeader{Type: msg.Header().Type})

	// Devices are visible in all (i.e. the only) network namespaces,
	// matching Linux's default ib_devices_shared_netns=true.
	m.PutAttr(linux.RDMA_NLDEV_SYS_ATTR_NETNS_MODE, primitive.AllocateUint8(1))
	m.PutAttr(linux.RDMA_NLDEV_SYS_ATTR_COPY_ON_FORK, primitive.AllocateUint8(1))
	return nil
}

// chardevAttrs returns the parsed attributes of a GET_CHARDEV message.
func chardevAttrs(msg *nlmsg.Message) (map[uint16]nlmsg.BytesView, bool) {
	// nldev messages carry no fixed payload header: attributes immediately
	// follow the netlink header, so the fixed portion extracted by GetData is
	// empty.
	var empty primitive.ByteSlice
	attrsView, ok := msg.GetData(&empty)
	if !ok {
		return nil, false
	}
	return attrsView.Parse()
}

// parseNodeType parses a sysfs node_type string such as "1: CA".
func parseNodeType(s string) uint8 {
	num, _, _ := strings.Cut(s, ":")
	n, err := strconv.ParseUint(strings.TrimSpace(num), 10, 8)
	if err != nil {
		log.Warningf("Netlink RDMA: cannot parse node_type %q, defaulting to CA", s)
		return 1 // RDMA_NODE_IB_CA
	}
	return uint8(n)
}

// parseNodeGUID parses a sysfs node_guid string such as
// "0c42:a103:0065:2202" into raw big-endian bytes, the byte order Linux
// sends the __be64 GUID in.
func parseNodeGUID(s string) [8]byte {
	var guid [8]byte
	b, err := hex.DecodeString(strings.ReplaceAll(strings.TrimSpace(s), ":", ""))
	if err != nil || len(b) != len(guid) {
		log.Warningf("Netlink RDMA: cannot parse node_guid %q", s)
		return guid
	}
	copy(guid[:], b)
	return guid
}

// parseDevMinor returns the minor number of a sysfs dev file value, e.g.
// "231:192".
func parseDevMinor(s string) (uint32, bool) {
	_, minStr, found := strings.Cut(strings.TrimSpace(s), ":")
	if !found {
		return 0, false
	}
	n, err := strconv.ParseUint(minStr, 10, 32)
	if err != nil {
		return 0, false
	}
	return uint32(n), true
}

// parseUint64 parses a decimal sysfs value, returning 0 on error. Snapshot
// attribute values are verbatim sysfs file contents including the trailing
// newline, hence the trim.
func parseUint64(s string) uint64 {
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// init registers the NETLINK_RDMA provider.
func init() {
	netlink.RegisterProvider(linux.NETLINK_RDMA, NewProtocol)
}
