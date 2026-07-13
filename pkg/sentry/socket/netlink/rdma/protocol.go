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
// RDMA_NLDEV_CMD_GET_CHARDEV for "uverbs"), librdmacm ABI detection
// (RDMA_NLDEV_CMD_GET_CHARDEV for "rdma_cm"), and fork safety detection
// (RDMA_NLDEV_CMD_SYS_GET).
package rdma

import (
	"encoding/hex"
	"strconv"
	"strings"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/devices/rdmaproxy"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/sys"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/socket/netlink"
	"gvisor.dev/gvisor/pkg/sentry/socket/netlink/nlmsg"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/syserr"
)

var (
	devMu sync.RWMutex
	// devData is the RDMA device data collected from host sysfs, or nil if
	// rdmaproxy is disabled.
	devData *sys.RDMAData
)

// Init publishes RDMA device data to NETLINK_RDMA sockets. The loader calls
// it during boot, before application sockets can be created. If it is never
// called (or called with nil), socket(AF_NETLINK, ..., NETLINK_RDMA) fails
// with EPROTONOSUPPORT, matching a host kernel without RDMA support.
func Init(data *sys.RDMAData) {
	devMu.Lock()
	defer devMu.Unlock()
	devData = data
}

// deviceData returns the RDMA device data, or nil if rdmaproxy is disabled.
func deviceData() *sys.RDMAData {
	devMu.RLock()
	defer devMu.RUnlock()
	return devData
}

// Protocol implements netlink.Protocol.
//
// +stateify savable
type Protocol struct{}

var _ netlink.Protocol = (*Protocol)(nil)

// NewProtocol creates a NETLINK_RDMA netlink.Protocol.
func NewProtocol(t *kernel.Task) (netlink.Protocol, *syserr.Error) {
	if deviceData() == nil {
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

	data := deviceData()
	if data == nil {
		// Sockets can only be created after Init publishes non-nil data, so
		// this is only reachable if the data was cleared afterwards.
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
func (p *Protocol) dumpDevices(data *sys.RDMAData, msg *nlmsg.Message, ms *nlmsg.MessageSet) *syserr.Error {
	hdr := msg.Header()
	// Only the dump variant is supported; the doit variant is unused by
	// rdma-core.
	if hdr.Flags&linux.NLM_F_DUMP != linux.NLM_F_DUMP {
		return syserr.ErrNotSupported
	}

	// Must be set before AddMessage so that NLM_F_MULTI is set on each
	// message, and so that an NLMSG_DONE message terminates the dump.
	ms.Multi = true

	for i, dev := range data.Devices {
		m := ms.AddMessage(linux.NetlinkMessageHeader{
			Type: hdr.Type,
		})
		m.PutAttr(linux.RDMA_NLDEV_ATTR_DEV_INDEX, primitive.AllocateUint32(uint32(i)))
		m.PutAttrString(linux.RDMA_NLDEV_ATTR_DEV_NAME, dev.IBDev)
		// In CMD_GET responses, PORT_INDEX carries the port count.
		m.PutAttr(linux.RDMA_NLDEV_ATTR_PORT_INDEX, primitive.AllocateUint32(uint32(len(dev.Ports))))
		m.PutAttr(linux.RDMA_NLDEV_ATTR_DEV_NODE_TYPE, primitive.AllocateUint8(parseNodeType(dev.NodeType)))
		guid := parseNodeGUID(dev.NodeGUID)
		guidAttr := primitive.ByteSlice(guid[:])
		m.PutAttr(linux.RDMA_NLDEV_ATTR_NODE_GUID, &guidAttr)
	}
	return nil
}

// getChardev handles RDMA_NLDEV_CMD_GET_CHARDEV requests, from
// drivers/infiniband/core/nldev.c:nldev_get_chardev.
func (p *Protocol) getChardev(data *sys.RDMAData, msg *nlmsg.Message, ms *nlmsg.MessageSet) *syserr.Error {
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

		devNum, err := strconv.ParseUint(strings.TrimPrefix(dev.Name, "uverbs"), 10, 32)
		if err != nil {
			log.Warningf("Netlink RDMA: cannot parse device number from %q", dev.Name)
			return syserr.ErrInvalidArgument
		}
		major, minor, ok := rdmaproxy.UverbsDev(uint32(devNum))
		if !ok {
			log.Warningf("Netlink RDMA: %s is not registered", dev.Name)
			return syserr.ErrInvalidArgument
		}

		driverID, idOK := rdmaproxy.DriverID(dev.IBDev, dev.PCIDriver)
		if !idOK {
			log.Warningf("Netlink RDMA: no driver ID mapping for device %q (module %q)", dev.IBDev, dev.PCIDriver)
		}

		m := ms.AddMessage(linux.NetlinkMessageHeader{Type: hdr.Type})
		m.PutAttrString(linux.RDMA_NLDEV_ATTR_CHARDEV_NAME, dev.Name)
		m.PutAttr(linux.RDMA_NLDEV_ATTR_CHARDEV_ABI, primitive.AllocateUint64(parseUint64(dev.ABIVersion)))
		m.PutAttr(linux.RDMA_NLDEV_ATTR_CHARDEV, primitive.AllocateUint64(linux.HugeEncodeDev(major, minor)))
		m.PutAttr(linux.RDMA_NLDEV_ATTR_UVERBS_DRIVER_ID, primitive.AllocateUint32(driverID))
		return nil

	case "rdma_cm":
		major, minor, ok := rdmaproxy.RDMACMDev()
		if !ok {
			return syserr.ErrInvalidArgument
		}
		abi := parseUint64(data.RDMACMABIVersion)
		if abi == 0 {
			// RDMA_USER_CM_ABI_VERSION; stable since Linux 2.6.
			abi = 4
		}
		m := ms.AddMessage(linux.NetlinkMessageHeader{Type: hdr.Type})
		m.PutAttrString(linux.RDMA_NLDEV_ATTR_CHARDEV_NAME, "rdma_cm")
		m.PutAttr(linux.RDMA_NLDEV_ATTR_CHARDEV_ABI, primitive.AllocateUint64(abi))
		m.PutAttr(linux.RDMA_NLDEV_ATTR_CHARDEV, primitive.AllocateUint64(linux.HugeEncodeDev(major, minor)))
		return nil

	default:
		// Linux fails with ENOENT when no client matches the requested
		// type (ib_get_client_nl_info).
		log.Debugf("Netlink RDMA: unsupported chardev type %q", typ)
		return syserr.ErrNoFileOrDir
	}
}

// sysGet handles RDMA_NLDEV_CMD_SYS_GET requests, from
// drivers/infiniband/core/nldev.c:nldev_sys_get_doit.
func (p *Protocol) sysGet(msg *nlmsg.Message, ms *nlmsg.MessageSet) *syserr.Error {
	m := ms.AddMessage(linux.NetlinkMessageHeader{Type: msg.Header().Type})
	// Devices are visible in all (i.e. the only) network namespaces,
	// matching Linux's default ib_devices_shared_netns=true.
	m.PutAttr(linux.RDMA_NLDEV_SYS_ATTR_NETNS_MODE, primitive.AllocateUint8(1))
	// The sentry's emulated fork does not implement Linux 5.12's DMA-safe
	// copy-on-fork: mm.Fork COW-shares pinned private pages and a
	// post-fork write moves the writer to a new frame while the NIC
	// continues DMA to the pinned one. Report 0 so that libibverbs uses
	// its MADV_DONTFORK tracking instead.
	m.PutAttr(linux.RDMA_NLDEV_SYS_ATTR_COPY_ON_FORK, primitive.AllocateUint8(0))
	return nil
}

// chardevAttrs returns the parsed attributes of a GET_CHARDEV message.
// nldev messages carry no fixed payload header: attributes immediately
// follow the netlink header (Linux parses them with nlmsg_parse(nlh, 0,
// ...)), so the fixed portion extracted by GetData is empty.
func chardevAttrs(msg *nlmsg.Message) (map[uint16]nlmsg.BytesView, bool) {
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

// parseUint64 parses a decimal sysfs value, returning 0 on error.
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
