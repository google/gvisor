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

package proc

import (
	"bytes"
	"fmt"
	"io"
	"reflect"
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/proc/seqfile"
	"gvisor.dev/gvisor/pkg/sentry/fs/ramfs"
	"gvisor.dev/gvisor/pkg/sentry/inet"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/socket"
	"gvisor.dev/gvisor/pkg/sentry/socket/unix"
	"gvisor.dev/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/usermem"
)

// LINT.IfChange

// newNetDir creates a new proc net entry.
func newNetDir(ctx context.Context, t *kernel.Task, msrc *fs.MountSource) *fs.Inode {
	k := t.Kernel()

	var contents map[string]*fs.Inode
	if s := t.NetworkNamespace().Stack(); s != nil {
		// TODO(gvisor.dev/issue/1833): Make sure file contents reflect the task
		// network namespace.
		contents = map[string]*fs.Inode{
			"dev":  seqfile.NewSeqFileInode(ctx, &netDev{s: s}, msrc),
			"snmp": seqfile.NewSeqFileInode(ctx, &netSnmp{s: s}, msrc),

			// The following files are simple stubs until they are
			// implemented in netstack, if the file contains a
			// header the stub is just the header otherwise it is
			// an empty file.
			"arp": newStaticProcInode(ctx, msrc, []byte("IP address       HW type     Flags       HW address            Mask     Device\n")),

			"netlink":   newStaticProcInode(ctx, msrc, []byte("sk       Eth Pid    Groups   Rmem     Wmem     Dump     Locks     Drops     Inode\n")),
			"netstat":   newStaticProcInode(ctx, msrc, []byte("TcpExt: SyncookiesSent SyncookiesRecv SyncookiesFailed EmbryonicRsts PruneCalled RcvPruned OfoPruned OutOfWindowIcmps LockDroppedIcmps ArpFilter TW TWRecycled TWKilled PAWSPassive PAWSActive PAWSEstab DelayedACKs DelayedACKLocked DelayedACKLost ListenOverflows ListenDrops TCPPrequeued TCPDirectCopyFromBacklog TCPDirectCopyFromPrequeue TCPPrequeueDropped TCPHPHits TCPHPHitsToUser TCPPureAcks TCPHPAcks TCPRenoRecovery TCPSackRecovery TCPSACKReneging TCPFACKReorder TCPSACKReorder TCPRenoReorder TCPTSReorder TCPFullUndo TCPPartialUndo TCPDSACKUndo TCPLossUndo TCPLostRetransmit TCPRenoFailures TCPSackFailures TCPLossFailures TCPFastRetrans TCPForwardRetrans TCPSlowStartRetrans TCPTimeouts TCPLossProbes TCPLossProbeRecovery TCPRenoRecoveryFail TCPSackRecoveryFail TCPSchedulerFailed TCPRcvCollapsed TCPDSACKOldSent TCPDSACKOfoSent TCPDSACKRecv TCPDSACKOfoRecv TCPAbortOnData TCPAbortOnClose TCPAbortOnMemory TCPAbortOnTimeout TCPAbortOnLinger TCPAbortFailed TCPMemoryPressures TCPSACKDiscard TCPDSACKIgnoredOld TCPDSACKIgnoredNoUndo TCPSpuriousRTOs TCPMD5NotFound TCPMD5Unexpected TCPMD5Failure TCPSackShifted TCPSackMerged TCPSackShiftFallback TCPBacklogDrop TCPMinTTLDrop TCPDeferAcceptDrop IPReversePathFilter TCPTimeWaitOverflow TCPReqQFullDoCookies TCPReqQFullDrop TCPRetransFail TCPRcvCoalesce TCPOFOQueue TCPOFODrop TCPOFOMerge TCPChallengeACK TCPSYNChallenge TCPFastOpenActive TCPFastOpenActiveFail TCPFastOpenPassive TCPFastOpenPassiveFail TCPFastOpenListenOverflow TCPFastOpenCookieReqd TCPSpuriousRtxHostQueues BusyPollRxPackets TCPAutoCorking TCPFromZeroWindowAdv TCPToZeroWindowAdv TCPWantZeroWindowAdv TCPSynRetrans TCPOrigDataSent TCPHystartTrainDetect TCPHystartTrainCwnd TCPHystartDelayDetect TCPHystartDelayCwnd TCPACKSkippedSynRecv TCPACKSkippedPAWS TCPACKSkippedSeq TCPACKSkippedFinWait2 TCPACKSkippedTimeWait TCPACKSkippedChallenge TCPWinProbe TCPKeepAlive TCPMTUPFail TCPMTUPSuccess\n")),
			"packet":    newStaticProcInode(ctx, msrc, []byte("sk       RefCnt Type Proto  Iface R Rmem   User   Inode\n")),
			"protocols": newStaticProcInode(ctx, msrc, []byte("protocol  size sockets  memory press maxhdr  slab module     cl co di ac io in de sh ss gs se re sp bi br ha uh gp em\n")),
			// Linux sets psched values to: nsec per usec, psched
			// tick in ns, 1000000, high res timer ticks per sec
			// (ClockGetres returns 1ns resolution).
			"psched": newStaticProcInode(ctx, msrc, []byte(fmt.Sprintf("%08x %08x %08x %08x\n", uint64(time.Microsecond/time.Nanosecond), 64, 1000000, uint64(time.Second/time.Nanosecond)))),
			"ptype":  newStaticProcInode(ctx, msrc, []byte("Type Device      Function\n")),
			"route":  seqfile.NewSeqFileInode(ctx, &netRoute{s: s}, msrc),
			"tcp":    seqfile.NewSeqFileInode(ctx, &netTCP{k: k}, msrc),
			"udp":    seqfile.NewSeqFileInode(ctx, &netUDP{k: k}, msrc),
			"unix":   seqfile.NewSeqFileInode(ctx, &netUnix{k: k}, msrc),
		}

		if s.SupportsIPv6() {
			contents["if_inet6"] = seqfile.NewSeqFileInode(ctx, &ifinet6{s: s}, msrc)
			contents["ipv6_route"] = newStaticProcInode(ctx, msrc, []byte(""))
			contents["tcp6"] = seqfile.NewSeqFileInode(ctx, &netTCP6{k: k}, msrc)
			contents["udp6"] = newStaticProcInode(ctx, msrc, []byte("  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"))
		}
	}
	d := ramfs.NewDir(ctx, contents, fs.RootOwner, fs.FilePermsFromMode(0555))
	return newProcInode(ctx, d, msrc, fs.SpecialDirectory, t)
}

// ifinet6 implements seqfile.SeqSource for /proc/net/if_inet6.
//
// +stateify savable
type ifinet6 struct {
	s inet.Stack
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
func (n *ifinet6) ReadSeqFileData(ctx context.Context, h seqfile.SeqHandle) ([]seqfile.SeqData, int64) {
	contents := n.contents()
	minI := 0
	if h != nil {
		minI = h.(int) + 1
		if minI > len(contents) {
			minI = len(contents)
		}
	}
	var data []seqfile.SeqData
	for i, l := range contents[minI:] {
		data = append(data, seqfile.SeqData{Buf: []byte(l), Handle: i + minI})
	}

	return data, 0
}

// netDev implements seqfile.SeqSource for /proc/net/dev.
//
// +stateify savable
type netDev struct {
	s inet.Stack
}

// NeedsUpdate implements seqfile.SeqSource.NeedsUpdate.
func (n *netDev) NeedsUpdate(generation int64) bool {
	return true
}

// ReadSeqFileData implements seqfile.SeqSource.ReadSeqFileData. See Linux's
// net/core/net-procfs.c:dev_seq_show.
func (n *netDev) ReadSeqFileData(ctx context.Context, h seqfile.SeqHandle) ([]seqfile.SeqData, int64) {
	interfaces := n.s.Interfaces()
	contents := make([]string, 2, 2+len(interfaces))
	// Add the table header. From net/core/net-procfs.c:dev_seq_show.
	contents[0] = "Inter-|   Receive                                                |  Transmit\n"
	contents[1] = " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"

	for _, i := range interfaces {
		// Implements the same format as
		// net/core/net-procfs.c:dev_seq_printf_stats.
		var stats inet.StatDev
		if err := n.s.Statistics(&stats, i.Name); err != nil {
			log.Warningf("Failed to retrieve interface statistics for %v: %v", i.Name, err)
			continue
		}
		l := fmt.Sprintf(
			"%6s: %7d %7d %4d %4d %4d %5d %10d %9d %8d %7d %4d %4d %4d %5d %7d %10d\n",
			i.Name,
			// Received
			stats[0], // bytes
			stats[1], // packets
			stats[2], // errors
			stats[3], // dropped
			stats[4], // fifo
			stats[5], // frame
			stats[6], // compressed
			stats[7], // multicast
			// Transmitted
			stats[8],  // bytes
			stats[9],  // packets
			stats[10], // errors
			stats[11], // dropped
			stats[12], // fifo
			stats[13], // frame
			stats[14], // compressed
			stats[15]) // multicast
		contents = append(contents, l)
	}

	minI := 0
	if h != nil {
		minI = h.(int) + 1
		if minI > len(contents) {
			minI = len(contents)
		}
	}
	var data []seqfile.SeqData
	for i, l := range contents[minI:] {
		data = append(data, seqfile.SeqData{Buf: []byte(l), Handle: i + minI})
	}

	return data, 0
}

// netSnmp implements seqfile.SeqSource for /proc/net/snmp.
//
// +stateify savable
type netSnmp struct {
	s inet.Stack
}

// NeedsUpdate implements seqfile.SeqSource.NeedsUpdate.
func (n *netSnmp) NeedsUpdate(generation int64) bool {
	return true
}

type snmpLine struct {
	prefix string
	header string
}

var snmp = []snmpLine{
	{
		prefix: "Ip",
		header: "Forwarding DefaultTTL InReceives InHdrErrors InAddrErrors ForwDatagrams InUnknownProtos InDiscards InDelivers OutRequests OutDiscards OutNoRoutes ReasmTimeout ReasmReqds ReasmOKs ReasmFails FragOKs FragFails FragCreates",
	},
	{
		prefix: "Icmp",
		header: "InMsgs InErrors InCsumErrors InDestUnreachs InTimeExcds InParmProbs InSrcQuenchs InRedirects InEchos InEchoReps InTimestamps InTimestampReps InAddrMasks InAddrMaskReps OutMsgs OutErrors OutDestUnreachs OutTimeExcds OutParmProbs OutSrcQuenchs OutRedirects OutEchos OutEchoReps OutTimestamps OutTimestampReps OutAddrMasks OutAddrMaskReps",
	},
	{
		prefix: "IcmpMsg",
	},
	{
		prefix: "Tcp",
		header: "RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens AttemptFails EstabResets CurrEstab InSegs OutSegs RetransSegs InErrs OutRsts InCsumErrors",
	},
	{
		prefix: "Udp",
		header: "InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti",
	},
	{
		prefix: "UdpLite",
		header: "InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti",
	},
}

func toSlice(a interface{}) []uint64 {
	v := reflect.Indirect(reflect.ValueOf(a))
	return v.Slice(0, v.Len()).Interface().([]uint64)
}

func sprintSlice(s []uint64) string {
	if len(s) == 0 {
		return ""
	}
	r := fmt.Sprint(s)
	return r[1 : len(r)-1] // Remove "[]" introduced by fmt of slice.
}

// ReadSeqFileData implements seqfile.SeqSource.ReadSeqFileData. See Linux's
// net/core/net-procfs.c:dev_seq_show.
func (n *netSnmp) ReadSeqFileData(ctx context.Context, h seqfile.SeqHandle) ([]seqfile.SeqData, int64) {
	contents := make([]string, 0, len(snmp)*2)
	types := []interface{}{
		&inet.StatSNMPIP{},
		&inet.StatSNMPICMP{},
		nil, // TODO(gvisor.dev/issue/628): Support IcmpMsg stats.
		&inet.StatSNMPTCP{},
		&inet.StatSNMPUDP{},
		&inet.StatSNMPUDPLite{},
	}
	for i, stat := range types {
		line := snmp[i]
		if stat == nil {
			contents = append(
				contents,
				fmt.Sprintf("%s:\n", line.prefix),
				fmt.Sprintf("%s:\n", line.prefix),
			)
			continue
		}
		if err := n.s.Statistics(stat, line.prefix); err != nil {
			if err == syserror.EOPNOTSUPP {
				log.Infof("Failed to retrieve %s of /proc/net/snmp: %v", line.prefix, err)
			} else {
				log.Warningf("Failed to retrieve %s of /proc/net/snmp: %v", line.prefix, err)
			}
		}
		var values string
		if line.prefix == "Tcp" {
			tcp := stat.(*inet.StatSNMPTCP)
			// "Tcp" needs special processing because MaxConn is signed. RFC 2012.
			values = fmt.Sprintf("%s %d %s", sprintSlice(tcp[:3]), int64(tcp[3]), sprintSlice(tcp[4:]))
		} else {
			values = sprintSlice(toSlice(stat))
		}
		contents = append(
			contents,
			fmt.Sprintf("%s: %s\n", line.prefix, line.header),
			fmt.Sprintf("%s: %s\n", line.prefix, values),
		)
	}

	minI := 0
	if h != nil {
		minI = h.(int) + 1
		if minI > len(contents) {
			minI = len(contents)
		}
	}
	data := make([]seqfile.SeqData, 0, len(snmp)*2)
	for i, l := range contents[minI:] {
		data = append(data, seqfile.SeqData{Buf: []byte(l), Handle: i + minI})
	}

	return data, 0
}

// netRoute implements seqfile.SeqSource for /proc/net/route.
//
// +stateify savable
type netRoute struct {
	s inet.Stack
}

// NeedsUpdate implements seqfile.SeqSource.NeedsUpdate.
func (n *netRoute) NeedsUpdate(generation int64) bool {
	return true
}

// ReadSeqFileData implements seqfile.SeqSource.ReadSeqFileData.
// See Linux's net/ipv4/fib_trie.c:fib_route_seq_show.
func (n *netRoute) ReadSeqFileData(ctx context.Context, h seqfile.SeqHandle) ([]seqfile.SeqData, int64) {
	interfaces := n.s.Interfaces()
	contents := []string{"Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT"}
	for _, rt := range n.s.RouteTable() {
		// /proc/net/route only includes ipv4 routes.
		if rt.Family != linux.AF_INET {
			continue
		}

		// /proc/net/route does not include broadcast or multicast routes.
		if rt.Type == linux.RTN_BROADCAST || rt.Type == linux.RTN_MULTICAST {
			continue
		}

		iface, ok := interfaces[rt.OutputInterface]
		if !ok || iface.Name == "lo" {
			continue
		}

		var (
			gw     uint32
			prefix uint32
			flags  = linux.RTF_UP
		)
		if len(rt.GatewayAddr) == header.IPv4AddressSize {
			flags |= linux.RTF_GATEWAY
			gw = usermem.ByteOrder.Uint32(rt.GatewayAddr)
		}
		if len(rt.DstAddr) == header.IPv4AddressSize {
			prefix = usermem.ByteOrder.Uint32(rt.DstAddr)
		}
		l := fmt.Sprintf(
			"%s\t%08X\t%08X\t%04X\t%d\t%d\t%d\t%08X\t%d\t%d\t%d",
			iface.Name,
			prefix,
			gw,
			flags,
			0, // RefCnt.
			0, // Use.
			0, // Metric.
			(uint32(1)<<rt.DstLen)-1,
			0, // MTU.
			0, // Window.
			0, // RTT.
		)
		contents = append(contents, l)
	}

	minI := 0
	if h != nil {
		minI = h.(int) + 1
		if minI > len(contents) {
			minI = len(contents)
		}
	}
	var data []seqfile.SeqData
	for i, l := range contents[minI:] {
		l = fmt.Sprintf("%-127s\n", l)
		data = append(data, seqfile.SeqData{Buf: []byte(l), Handle: i + minI})
	}

	return data, 0
}

// netUnix implements seqfile.SeqSource for /proc/net/unix.
//
// +stateify savable
type netUnix struct {
	k *kernel.Kernel
}

// NeedsUpdate implements seqfile.SeqSource.NeedsUpdate.
func (*netUnix) NeedsUpdate(generation int64) bool {
	return true
}

// ReadSeqFileData implements seqfile.SeqSource.ReadSeqFileData.
func (n *netUnix) ReadSeqFileData(ctx context.Context, h seqfile.SeqHandle) ([]seqfile.SeqData, int64) {
	var buf bytes.Buffer
	for _, se := range n.k.ListSockets() {
		s := se.Sock.Get()
		if s == nil {
			log.Debugf("Couldn't resolve weakref with ID %v in socket table, racing with destruction?", se.ID)
			continue
		}
		sfile := s.(*fs.File)
		if family, _, _ := sfile.FileOperations.(socket.Socket).Type(); family != linux.AF_UNIX {
			s.DecRef(ctx)
			// Not a unix socket.
			continue
		}
		sops := sfile.FileOperations.(*unix.SocketOperations)

		addr, err := sops.Endpoint().GetLocalAddress()
		if err != nil {
			log.Warningf("Failed to retrieve socket name from %+v: %v", sfile, err)
			addr.Addr = "<unknown>"
		}

		sockFlags := 0
		if ce, ok := sops.Endpoint().(transport.ConnectingEndpoint); ok {
			if ce.Listening() {
				// For unix domain sockets, linux reports a single flag
				// value if the socket is listening, of __SO_ACCEPTCON.
				sockFlags = linux.SO_ACCEPTCON
			}
		}

		// In the socket entry below, the value for the 'Num' field requires
		// some consideration. Linux prints the address to the struct
		// unix_sock representing a socket in the kernel, but may redact the
		// value for unprivileged users depending on the kptr_restrict
		// sysctl.
		//
		// One use for this field is to allow a privileged user to
		// introspect into the kernel memory to determine information about
		// a socket not available through procfs, such as the socket's peer.
		//
		// On gvisor, returning a pointer to our internal structures would
		// be pointless, as it wouldn't match the memory layout for struct
		// unix_sock, making introspection difficult. We could populate a
		// struct unix_sock with the appropriate data, but even that
		// requires consideration for which kernel version to emulate, as
		// the definition of this struct changes over time.
		//
		// For now, we always redact this pointer.
		fmt.Fprintf(&buf, "%#016p: %08X %08X %08X %04X %02X %5d",
			(*unix.SocketOperations)(nil), // Num, pointer to kernel socket struct.
			sfile.ReadRefs()-1,            // RefCount, don't count our own ref.
			0,                             // Protocol, always 0 for UDS.
			sockFlags,                     // Flags.
			sops.Endpoint().Type(),        // Type.
			sops.State(),                  // State.
			sfile.InodeID(),               // Inode.
		)

		// Path
		if len(addr.Addr) != 0 {
			if addr.Addr[0] == 0 {
				// Abstract path.
				fmt.Fprintf(&buf, " @%s", string(addr.Addr[1:]))
			} else {
				fmt.Fprintf(&buf, " %s", string(addr.Addr))
			}
		}
		fmt.Fprintf(&buf, "\n")

		s.DecRef(ctx)
	}

	minI := 0
	if h != nil {
		minI = h.(int) + 1
	}
	var data []seqfile.SeqData
	if minI <= 0 {
		data = append(data, seqfile.SeqData{
			Buf:    []byte("Num       RefCount Protocol Flags    Type St Inode Path\n"),
			Handle: 0,
		})
	}
	if minI <= 1 {
		data = append(data, seqfile.SeqData{
			Buf:    buf.Bytes(),
			Handle: 1,
		})
	}
	return data, 0
}

func networkToHost16(n uint16) uint16 {
	// n is in network byte order, so is big-endian. The most-significant byte
	// should be stored in the lower address.
	//
	// We manually inline binary.BigEndian.Uint16() because Go does not support
	// non-primitive consts, so binary.BigEndian is a (mutable) var, so calls to
	// binary.BigEndian.Uint16() require a read of binary.BigEndian and an
	// interface method call, defeating inlining.
	buf := [2]byte{byte(n >> 8 & 0xff), byte(n & 0xff)}
	return usermem.ByteOrder.Uint16(buf[:])
}

func writeInetAddr(w io.Writer, family int, i linux.SockAddr) {
	switch family {
	case linux.AF_INET:
		var a linux.SockAddrInet
		if i != nil {
			a = *i.(*linux.SockAddrInet)
		}

		// linux.SockAddrInet.Port is stored in the network byte order and is
		// printed like a number in host byte order. Note that all numbers in host
		// byte order are printed with the most-significant byte first when
		// formatted with %X. See get_tcp4_sock() and udp4_format_sock() in Linux.
		port := networkToHost16(a.Port)

		// linux.SockAddrInet.Addr is stored as a byte slice in big-endian order
		// (i.e. most-significant byte in index 0). Linux represents this as a
		// __be32 which is a typedef for an unsigned int, and is printed with
		// %X. This means that for a little-endian machine, Linux prints the
		// least-significant byte of the address first. To emulate this, we first
		// invert the byte order for the address using usermem.ByteOrder.Uint32,
		// which makes it have the equivalent encoding to a __be32 on a little
		// endian machine. Note that this operation is a no-op on a big endian
		// machine. Then similar to Linux, we format it with %X, which will print
		// the most-significant byte of the __be32 address first, which is now
		// actually the least-significant byte of the original address in
		// linux.SockAddrInet.Addr on little endian machines, due to the conversion.
		addr := usermem.ByteOrder.Uint32(a.Addr[:])

		fmt.Fprintf(w, "%08X:%04X ", addr, port)
	case linux.AF_INET6:
		var a linux.SockAddrInet6
		if i != nil {
			a = *i.(*linux.SockAddrInet6)
		}

		port := networkToHost16(a.Port)
		addr0 := usermem.ByteOrder.Uint32(a.Addr[0:4])
		addr1 := usermem.ByteOrder.Uint32(a.Addr[4:8])
		addr2 := usermem.ByteOrder.Uint32(a.Addr[8:12])
		addr3 := usermem.ByteOrder.Uint32(a.Addr[12:16])
		fmt.Fprintf(w, "%08X%08X%08X%08X:%04X ", addr0, addr1, addr2, addr3, port)
	}
}

func commonReadSeqFileDataTCP(ctx context.Context, n seqfile.SeqHandle, k *kernel.Kernel, h seqfile.SeqHandle, fa int, header []byte) ([]seqfile.SeqData, int64) {
	// t may be nil here if our caller is not part of a task goroutine. This can
	// happen for example if we're here for "sentryctl cat". When t is nil,
	// degrade gracefully and retrieve what we can.
	t := kernel.TaskFromContext(ctx)

	var buf bytes.Buffer
	for _, se := range k.ListSockets() {
		s := se.Sock.Get()
		if s == nil {
			log.Debugf("Couldn't resolve weakref with ID %v in socket table, racing with destruction?", se.ID)
			continue
		}
		sfile := s.(*fs.File)
		sops, ok := sfile.FileOperations.(socket.Socket)
		if !ok {
			panic(fmt.Sprintf("Found non-socket file in socket table: %+v", sfile))
		}
		if family, stype, _ := sops.Type(); !(family == fa && stype == linux.SOCK_STREAM) {
			s.DecRef(ctx)
			// Not tcp4 sockets.
			continue
		}

		// Linux's documentation for the fields below can be found at
		// https://www.kernel.org/doc/Documentation/networking/proc_net_tcp.txt.
		// For Linux's implementation, see net/ipv4/tcp_ipv4.c:get_tcp4_sock().
		// Note that the header doesn't contain labels for all the fields.

		// Field: sl; entry number.
		fmt.Fprintf(&buf, "%4d: ", se.ID)

		// Field: local_adddress.
		var localAddr linux.SockAddr
		if t != nil {
			if local, _, err := sops.GetSockName(t); err == nil {
				localAddr = local
			}
		}
		writeInetAddr(&buf, fa, localAddr)

		// Field: rem_address.
		var remoteAddr linux.SockAddr
		if t != nil {
			if remote, _, err := sops.GetPeerName(t); err == nil {
				remoteAddr = remote
			}
		}
		writeInetAddr(&buf, fa, remoteAddr)

		// Field: state; socket state.
		fmt.Fprintf(&buf, "%02X ", sops.State())

		// Field: tx_queue, rx_queue; number of packets in the transmit and
		// receive queue. Unimplemented.
		fmt.Fprintf(&buf, "%08X:%08X ", 0, 0)

		// Field: tr, tm->when; timer active state and number of jiffies
		// until timer expires. Unimplemented.
		fmt.Fprintf(&buf, "%02X:%08X ", 0, 0)

		// Field: retrnsmt; number of unrecovered RTO timeouts.
		// Unimplemented.
		fmt.Fprintf(&buf, "%08X ", 0)

		// Field: uid.
		uattr, err := sfile.Dirent.Inode.UnstableAttr(ctx)
		if err != nil {
			log.Warningf("Failed to retrieve unstable attr for socket file: %v", err)
			fmt.Fprintf(&buf, "%5d ", 0)
		} else {
			creds := auth.CredentialsFromContext(ctx)
			fmt.Fprintf(&buf, "%5d ", uint32(uattr.Owner.UID.In(creds.UserNamespace).OrOverflow()))
		}

		// Field: timeout; number of unanswered 0-window probes.
		// Unimplemented.
		fmt.Fprintf(&buf, "%8d ", 0)

		// Field: inode.
		fmt.Fprintf(&buf, "%8d ", sfile.InodeID())

		// Field: refcount. Don't count the ref we obtain while deferencing
		// the weakref to this socket.
		fmt.Fprintf(&buf, "%d ", sfile.ReadRefs()-1)

		// Field: Socket struct address. Redacted due to the same reason as
		// the 'Num' field in /proc/net/unix, see netUnix.ReadSeqFileData.
		fmt.Fprintf(&buf, "%#016p ", (*socket.Socket)(nil))

		// Field: retransmit timeout. Unimplemented.
		fmt.Fprintf(&buf, "%d ", 0)

		// Field: predicted tick of soft clock (delayed ACK control data).
		// Unimplemented.
		fmt.Fprintf(&buf, "%d ", 0)

		// Field: (ack.quick<<1)|ack.pingpong, Unimplemented.
		fmt.Fprintf(&buf, "%d ", 0)

		// Field: sending congestion window, Unimplemented.
		fmt.Fprintf(&buf, "%d ", 0)

		// Field: Slow start size threshold, -1 if threshold >= 0xFFFF.
		// Unimplemented, report as large threshold.
		fmt.Fprintf(&buf, "%d", -1)

		fmt.Fprintf(&buf, "\n")

		s.DecRef(ctx)
	}

	minI := 0
	if h != nil {
		minI = h.(int) + 1
	}
	var data []seqfile.SeqData
	if minI <= 0 {
		data = append(data, seqfile.SeqData{
			Buf:    header,
			Handle: 0,
		})
	}
	if minI <= 1 {
		data = append(data, seqfile.SeqData{
			Buf:    buf.Bytes(),
			Handle: 1,
		})
	}
	return data, 0
}

// netTCP implements seqfile.SeqSource for /proc/net/tcp.
//
// +stateify savable
type netTCP struct {
	k *kernel.Kernel
}

// NeedsUpdate implements seqfile.SeqSource.NeedsUpdate.
func (*netTCP) NeedsUpdate(generation int64) bool {
	return true
}

// ReadSeqFileData implements seqfile.SeqSource.ReadSeqFileData.
func (n *netTCP) ReadSeqFileData(ctx context.Context, h seqfile.SeqHandle) ([]seqfile.SeqData, int64) {
	header := []byte("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode                                                     \n")
	return commonReadSeqFileDataTCP(ctx, n, n.k, h, linux.AF_INET, header)
}

// netTCP6 implements seqfile.SeqSource for /proc/net/tcp6.
//
// +stateify savable
type netTCP6 struct {
	k *kernel.Kernel
}

// NeedsUpdate implements seqfile.SeqSource.NeedsUpdate.
func (*netTCP6) NeedsUpdate(generation int64) bool {
	return true
}

// ReadSeqFileData implements seqfile.SeqSource.ReadSeqFileData.
func (n *netTCP6) ReadSeqFileData(ctx context.Context, h seqfile.SeqHandle) ([]seqfile.SeqData, int64) {
	header := []byte("  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n")
	return commonReadSeqFileDataTCP(ctx, n, n.k, h, linux.AF_INET6, header)
}

// netUDP implements seqfile.SeqSource for /proc/net/udp.
//
// +stateify savable
type netUDP struct {
	k *kernel.Kernel
}

// NeedsUpdate implements seqfile.SeqSource.NeedsUpdate.
func (*netUDP) NeedsUpdate(generation int64) bool {
	return true
}

// ReadSeqFileData implements seqfile.SeqSource.ReadSeqFileData.
func (n *netUDP) ReadSeqFileData(ctx context.Context, h seqfile.SeqHandle) ([]seqfile.SeqData, int64) {
	// t may be nil here if our caller is not part of a task goroutine. This can
	// happen for example if we're here for "sentryctl cat". When t is nil,
	// degrade gracefully and retrieve what we can.
	t := kernel.TaskFromContext(ctx)

	var buf bytes.Buffer
	for _, se := range n.k.ListSockets() {
		s := se.Sock.Get()
		if s == nil {
			log.Debugf("Couldn't resolve weakref with ID %v in socket table, racing with destruction?", se.ID)
			continue
		}
		sfile := s.(*fs.File)
		sops, ok := sfile.FileOperations.(socket.Socket)
		if !ok {
			panic(fmt.Sprintf("Found non-socket file in socket table: %+v", sfile))
		}
		if family, stype, _ := sops.Type(); family != linux.AF_INET || stype != linux.SOCK_DGRAM {
			s.DecRef(ctx)
			// Not udp4 socket.
			continue
		}

		// For Linux's implementation, see net/ipv4/udp.c:udp4_format_sock().

		// Field: sl; entry number.
		fmt.Fprintf(&buf, "%5d: ", se.ID)

		// Field: local_adddress.
		var localAddr linux.SockAddrInet
		if t != nil {
			if local, _, err := sops.GetSockName(t); err == nil {
				localAddr = *local.(*linux.SockAddrInet)
			}
		}
		writeInetAddr(&buf, linux.AF_INET, &localAddr)

		// Field: rem_address.
		var remoteAddr linux.SockAddrInet
		if t != nil {
			if remote, _, err := sops.GetPeerName(t); err == nil {
				remoteAddr = *remote.(*linux.SockAddrInet)
			}
		}
		writeInetAddr(&buf, linux.AF_INET, &remoteAddr)

		// Field: state; socket state.
		fmt.Fprintf(&buf, "%02X ", sops.State())

		// Field: tx_queue, rx_queue; number of packets in the transmit and
		// receive queue. Unimplemented.
		fmt.Fprintf(&buf, "%08X:%08X ", 0, 0)

		// Field: tr, tm->when. Always 0 for UDP.
		fmt.Fprintf(&buf, "%02X:%08X ", 0, 0)

		// Field: retrnsmt. Always 0 for UDP.
		fmt.Fprintf(&buf, "%08X ", 0)

		// Field: uid.
		uattr, err := sfile.Dirent.Inode.UnstableAttr(ctx)
		if err != nil {
			log.Warningf("Failed to retrieve unstable attr for socket file: %v", err)
			fmt.Fprintf(&buf, "%5d ", 0)
		} else {
			creds := auth.CredentialsFromContext(ctx)
			fmt.Fprintf(&buf, "%5d ", uint32(uattr.Owner.UID.In(creds.UserNamespace).OrOverflow()))
		}

		// Field: timeout. Always 0 for UDP.
		fmt.Fprintf(&buf, "%8d ", 0)

		// Field: inode.
		fmt.Fprintf(&buf, "%8d ", sfile.InodeID())

		// Field: ref; reference count on the socket inode. Don't count the ref
		// we obtain while deferencing the weakref to this socket.
		fmt.Fprintf(&buf, "%d ", sfile.ReadRefs()-1)

		// Field: Socket struct address. Redacted due to the same reason as
		// the 'Num' field in /proc/net/unix, see netUnix.ReadSeqFileData.
		fmt.Fprintf(&buf, "%#016p ", (*socket.Socket)(nil))

		// Field: drops; number of dropped packets. Unimplemented.
		fmt.Fprintf(&buf, "%d", 0)

		fmt.Fprintf(&buf, "\n")

		s.DecRef(ctx)
	}

	minI := 0
	if h != nil {
		minI = h.(int) + 1
	}
	var data []seqfile.SeqData
	if minI <= 0 {
		data = append(data, seqfile.SeqData{
			Buf:    []byte("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops             \n"),
			Handle: 0,
		})
	}
	if minI <= 1 {
		data = append(data, seqfile.SeqData{
			Buf:    buf.Bytes(),
			Handle: 1,
		})
	}
	return data, 0
}

// LINT.ThenChange(../../fsimpl/proc/task_net.go)
