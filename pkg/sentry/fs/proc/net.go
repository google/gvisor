// Copyright 2018 Google Inc.
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

package proc

import (
	"fmt"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/proc/seqfile"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/ramfs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/inet"
)

// newNet creates a new proc net entry.
func (p *proc) newNetDir(ctx context.Context, msrc *fs.MountSource) *fs.Inode {
	d := &ramfs.Dir{}
	d.InitDir(ctx, nil, fs.RootOwner, fs.FilePermsFromMode(0555))
	if s := p.k.NetworkStack(); s != nil && s.SupportsIPv6() {
		d.AddChild(ctx, "dev", seqfile.NewSeqFileInode(ctx, &netDev{s: s}, msrc))
		d.AddChild(ctx, "if_inet6", seqfile.NewSeqFileInode(ctx, &ifinet6{s: s}, msrc))
	}
	return newFile(d, msrc, fs.SpecialDirectory, nil)
}

// ifinet6 implements seqfile.SeqSource for /proc/net/if_inet6.
type ifinet6 struct {
	s inet.Stack `state:"nosave"` // S/R-FIXME
}

func (n *ifinet6) contents() []string {
	var lines []string
	nics := n.s.Interfaces()
	for id, naddrs := range n.s.InterfaceAddrs() {
		nic, ok := nics[id]
		if !ok {
			// NIC was added after NICNames was called. We'll just
			// ignore it.
			continue
		}

		for _, a := range naddrs {
			// IPv6 only.
			if a.Family != linux.AF_INET6 {
				continue
			}

			// Fields:
			// IPv6 address displayed in 32 hexadecimal chars without colons
			// Netlink device number (interface index) in hexadecimal (use nic id)
			// Prefix length in hexadecimal
			// Scope value (use 0)
			// Interface flags
			// Device name
			lines = append(lines, fmt.Sprintf("%032x %02x %02x %02x %02x %8s\n", a.Addr, id, a.PrefixLen, 0, a.Flags, nic.Name))
		}
	}
	return lines
}

// NeedsUpdate implements seqfile.SeqSource.NeedsUpdate.
func (*ifinet6) NeedsUpdate(generation int64) bool {
	return true
}

// ReadSeqFileData implements seqfile.SeqSource.ReadSeqFileData.
func (n *ifinet6) ReadSeqFileData(h seqfile.SeqHandle) ([]seqfile.SeqData, int64) {
	if h != nil {
		return nil, 0
	}

	var data []seqfile.SeqData
	for _, l := range n.contents() {
		data = append(data, seqfile.SeqData{Buf: []byte(l), Handle: (*ifinet6)(nil)})
	}

	return data, 0
}

// netDev implements seqfile.SeqSource for /proc/net/dev.
type netDev struct {
	s inet.Stack `state:"nosave"` // S/R-FIXME
}

// NeedsUpdate implements seqfile.SeqSource.NeedsUpdate.
func (n *netDev) NeedsUpdate(generation int64) bool {
	return true
}

// ReadSeqFileData implements seqfile.SeqSource.ReadSeqFileData. See Linux's
// net/core/net-procfs.c:dev_seq_show.
func (n *netDev) ReadSeqFileData(h seqfile.SeqHandle) ([]seqfile.SeqData, int64) {
	if h != nil {
		return nil, 0
	}

	interfaces := n.s.Interfaces()
	contents := make([]string, 2, 2+len(interfaces))
	// Add the table header. From net/core/net-procfs.c:dev_seq_show.
	contents[0] = "Inter-|   Receive                                                |  Transmit\n"
	contents[1] = " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"

	for _, i := range interfaces {
		// TODO: Collect stats from each inet.Stack
		// implementation (hostinet, epsocket, and rpcinet).

		// Implements the same format as
		// net/core/net-procfs.c:dev_seq_printf_stats.
		l := fmt.Sprintf("%6s: %7d %7d %4d %4d %4d %5d %10d %9d %8d %7d %4d %4d %4d %5d %7d %10d\n",
			i.Name,
			// Received
			0, // bytes
			0, // packets
			0, // errors
			0, // dropped
			0, // fifo
			0, // frame
			0, // compressed
			0, // multicast
			// Transmitted
			0, // bytes
			0, // packets
			0, // errors
			0, // dropped
			0, // fifo
			0, // frame
			0, // compressed
			0) // multicast
		contents = append(contents, l)
	}

	var data []seqfile.SeqData
	for _, l := range contents {
		data = append(data, seqfile.SeqData{Buf: []byte(l), Handle: (*ifinet6)(nil)})
	}

	return data, 0
}
