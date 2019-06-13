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
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/proc/seqfile"
	"gvisor.dev/gvisor/pkg/sentry/fs/ramfs"
	"gvisor.dev/gvisor/pkg/sentry/inet"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/socket"
	"gvisor.dev/gvisor/pkg/sentry/socket/unix"
	"gvisor.dev/gvisor/pkg/sentry/socket/unix/transport"
)

// newNet creates a new proc net entry.
func (p *proc) newNetDir(ctx context.Context, k *kernel.Kernel, msrc *fs.MountSource) *fs.Inode {
	var contents map[string]*fs.Inode
	if s := p.k.NetworkStack(); s != nil {
		contents = map[string]*fs.Inode{
			"dev": seqfile.NewSeqFileInode(ctx, &netDev{s: s}, msrc),

			// The following files are simple stubs until they are
			// implemented in netstack, if the file contains a
			// header the stub is just the header otherwise it is
			// an empty file.
			"arp": newStaticProcInode(ctx, msrc, []byte("IP address       HW type     Flags       HW address            Mask     Device")),

			"netlink":   newStaticProcInode(ctx, msrc, []byte("sk       Eth Pid    Groups   Rmem     Wmem     Dump     Locks     Drops     Inode")),
			"netstat":   newStaticProcInode(ctx, msrc, []byte("TcpExt: SyncookiesSent SyncookiesRecv SyncookiesFailed EmbryonicRsts PruneCalled RcvPruned OfoPruned OutOfWindowIcmps LockDroppedIcmps ArpFilter TW TWRecycled TWKilled PAWSPassive PAWSActive PAWSEstab DelayedACKs DelayedACKLocked DelayedACKLost ListenOverflows ListenDrops TCPPrequeued TCPDirectCopyFromBacklog TCPDirectCopyFromPrequeue TCPPrequeueDropped TCPHPHits TCPHPHitsToUser TCPPureAcks TCPHPAcks TCPRenoRecovery TCPSackRecovery TCPSACKReneging TCPFACKReorder TCPSACKReorder TCPRenoReorder TCPTSReorder TCPFullUndo TCPPartialUndo TCPDSACKUndo TCPLossUndo TCPLostRetransmit TCPRenoFailures TCPSackFailures TCPLossFailures TCPFastRetrans TCPForwardRetrans TCPSlowStartRetrans TCPTimeouts TCPLossProbes TCPLossProbeRecovery TCPRenoRecoveryFail TCPSackRecoveryFail TCPSchedulerFailed TCPRcvCollapsed TCPDSACKOldSent TCPDSACKOfoSent TCPDSACKRecv TCPDSACKOfoRecv TCPAbortOnData TCPAbortOnClose TCPAbortOnMemory TCPAbortOnTimeout TCPAbortOnLinger TCPAbortFailed TCPMemoryPressures TCPSACKDiscard TCPDSACKIgnoredOld TCPDSACKIgnoredNoUndo TCPSpuriousRTOs TCPMD5NotFound TCPMD5Unexpected TCPMD5Failure TCPSackShifted TCPSackMerged TCPSackShiftFallback TCPBacklogDrop TCPMinTTLDrop TCPDeferAcceptDrop IPReversePathFilter TCPTimeWaitOverflow TCPReqQFullDoCookies TCPReqQFullDrop TCPRetransFail TCPRcvCoalesce TCPOFOQueue TCPOFODrop TCPOFOMerge TCPChallengeACK TCPSYNChallenge TCPFastOpenActive TCPFastOpenActiveFail TCPFastOpenPassive TCPFastOpenPassiveFail TCPFastOpenListenOverflow TCPFastOpenCookieReqd TCPSpuriousRtxHostQueues BusyPollRxPackets TCPAutoCorking TCPFromZeroWindowAdv TCPToZeroWindowAdv TCPWantZeroWindowAdv TCPSynRetrans TCPOrigDataSent TCPHystartTrainDetect TCPHystartTrainCwnd TCPHystartDelayDetect TCPHystartDelayCwnd TCPACKSkippedSynRecv TCPACKSkippedPAWS TCPACKSkippedSeq TCPACKSkippedFinWait2 TCPACKSkippedTimeWait TCPACKSkippedChallenge TCPWinProbe TCPKeepAlive TCPMTUPFail TCPMTUPSuccess")),
			"packet":    newStaticProcInode(ctx, msrc, []byte("sk       RefCnt Type Proto  Iface R Rmem   User   Inode")),
			"protocols": newStaticProcInode(ctx, msrc, []byte("protocol  size sockets  memory press maxhdr  slab module     cl co di ac io in de sh ss gs se re sp bi br ha uh gp em")),
			// Linux sets psched values to: nsec per usec, psched
			// tick in ns, 1000000, high res timer ticks per sec
			// (ClockGetres returns 1ns resolution).
			"psched": newStaticProcInode(ctx, msrc, []byte(fmt.Sprintf("%08x %08x %08x %08x\n", uint64(time.Microsecond/time.Nanosecond), 64, 1000000, uint64(time.Second/time.Nanosecond)))),
			"ptype":  newStaticProcInode(ctx, msrc, []byte("Type Device      Function")),
			"route":  newStaticProcInode(ctx, msrc, []byte("Iface   Destination     Gateway         Flags   RefCnt  Use     Metric  Mask            MTU     Window  IRTT")),
			"tcp":    newStaticProcInode(ctx, msrc, []byte("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode")),

			"udp": newStaticProcInode(ctx, msrc, []byte("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops")),

			"unix": seqfile.NewSeqFileInode(ctx, &netUnix{k: k}, msrc),
		}

		if s.SupportsIPv6() {
			contents["if_inet6"] = seqfile.NewSeqFileInode(ctx, &ifinet6{s: s}, msrc)
			contents["ipv6_route"] = newStaticProcInode(ctx, msrc, []byte(""))
			contents["tcp6"] = newStaticProcInode(ctx, msrc, []byte("  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"))
			contents["udp6"] = newStaticProcInode(ctx, msrc, []byte("  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"))
		}
	}
	d := ramfs.NewDir(ctx, contents, fs.RootOwner, fs.FilePermsFromMode(0555))
	return newProcInode(d, msrc, fs.SpecialDirectory, nil)
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
	if h != nil {
		return nil, 0
	}

	interfaces := n.s.Interfaces()
	contents := make([]string, 2, 2+len(interfaces))
	// Add the table header. From net/core/net-procfs.c:dev_seq_show.
	contents[0] = "Inter-|   Receive                                                |  Transmit\n"
	contents[1] = " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"

	for _, i := range interfaces {
		// TODO(b/71872867): Collect stats from each inet.Stack
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
	if h != nil {
		return []seqfile.SeqData{}, 0
	}

	var buf bytes.Buffer
	// Header
	fmt.Fprintf(&buf, "Num       RefCount Protocol Flags    Type St Inode Path\n")

	// Entries
	for _, se := range n.k.ListSockets() {
		s := se.Sock.Get()
		if s == nil {
			log.Debugf("Couldn't resolve weakref %v in socket table, racing with destruction?", se.Sock)
			continue
		}
		sfile := s.(*fs.File)
		if family, _, _ := sfile.FileOperations.(socket.Socket).Type(); family != linux.AF_UNIX {
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

		sfile.DecRef()
	}

	data := []seqfile.SeqData{{
		Buf:    buf.Bytes(),
		Handle: (*netUnix)(nil),
	}}
	return data, 0
}
