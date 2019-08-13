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

package proc

import (
	"bytes"
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/binary"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/inet"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/socket"
	"gvisor.dev/gvisor/pkg/sentry/socket/unix"
	"gvisor.dev/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// ifinet6 implements vfs.DynamicBytesSource for /proc/net/if_inet6.
//
// +stateify savable
type ifinet6 struct {
	s inet.Stack
}

var _ vfs.DynamicBytesSource = (*ifinet6)(nil)

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

// Generate implements vfs.DynamicBytesSource.Generate.
func (n *ifinet6) Generate(ctx context.Context, buf *bytes.Buffer) error {
	for _, l := range n.contents() {
		buf.WriteString(l)
	}
	return nil
}

// netDev implements vfs.DynamicBytesSource for /proc/net/dev.
//
// +stateify savable
type netDev struct {
	s inet.Stack
}

var _ vfs.DynamicBytesSource = (*netDev)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
func (n *netDev) Generate(ctx context.Context, buf *bytes.Buffer) error {
	interfaces := n.s.Interfaces()
	buf.WriteString("Inter-|   Receive                                                |  Transmit\n")
	buf.WriteString(" face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n")

	for _, i := range interfaces {
		// Implements the same format as
		// net/core/net-procfs.c:dev_seq_printf_stats.
		var stats inet.StatDev
		if err := n.s.Statistics(&stats, i.Name); err != nil {
			log.Warningf("Failed to retrieve interface statistics for %v: %v", i.Name, err)
			continue
		}
		fmt.Fprintf(
			buf,
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
			stats[15], // multicast
		)
	}

	return nil
}

// netUnix implements vfs.DynamicBytesSource for /proc/net/unix.
//
// +stateify savable
type netUnix struct {
	k *kernel.Kernel
}

var _ vfs.DynamicBytesSource = (*netUnix)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
func (n *netUnix) Generate(ctx context.Context, buf *bytes.Buffer) error {
	buf.WriteString("Num       RefCount Protocol Flags    Type St Inode Path\n")
	for _, se := range n.k.ListSockets() {
		s := se.Sock.Get()
		if s == nil {
			log.Debugf("Couldn't resolve weakref %v in socket table, racing with destruction?", se.Sock)
			continue
		}
		sfile := s.(*fs.File)
		if family, _, _ := sfile.FileOperations.(socket.Socket).Type(); family != linux.AF_UNIX {
			s.DecRef()
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
		// In gvisor, returning a pointer to our internal structures would
		// be pointless, as it wouldn't match the memory layout for struct
		// unix_sock, making introspection difficult. We could populate a
		// struct unix_sock with the appropriate data, but even that
		// requires consideration for which kernel version to emulate, as
		// the definition of this struct changes over time.
		//
		// For now, we always redact this pointer.
		fmt.Fprintf(buf, "%#016p: %08X %08X %08X %04X %02X %5d",
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
				fmt.Fprintf(buf, " @%s", string(addr.Addr[1:]))
			} else {
				fmt.Fprintf(buf, " %s", string(addr.Addr))
			}
		}
		fmt.Fprintf(buf, "\n")

		s.DecRef()
	}
	return nil
}

// netTCP implements vfs.DynamicBytesSource for /proc/net/tcp.
//
// +stateify savable
type netTCP struct {
	k *kernel.Kernel
}

var _ vfs.DynamicBytesSource = (*netTCP)(nil)

func (n *netTCP) Generate(ctx context.Context, buf *bytes.Buffer) error {
	t := kernel.TaskFromContext(ctx)
	buf.WriteString("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode                                                     \n")
	for _, se := range n.k.ListSockets() {
		s := se.Sock.Get()
		if s == nil {
			log.Debugf("Couldn't resolve weakref %+v in socket table, racing with destruction?", se.Sock)
			continue
		}
		sfile := s.(*fs.File)
		sops, ok := sfile.FileOperations.(socket.Socket)
		if !ok {
			panic(fmt.Sprintf("Found non-socket file in socket table: %+v", sfile))
		}
		if family, stype, _ := sops.Type(); !(family == linux.AF_INET && stype == linux.SOCK_STREAM) {
			s.DecRef()
			// Not tcp4 sockets.
			continue
		}

		// Linux's documentation for the fields below can be found at
		// https://www.kernel.org/doc/Documentation/networking/proc_net_tcp.txt.
		// For Linux's implementation, see net/ipv4/tcp_ipv4.c:get_tcp4_sock().
		// Note that the header doesn't contain labels for all the fields.

		// Field: sl; entry number.
		fmt.Fprintf(buf, "%4d: ", se.ID)

		portBuf := make([]byte, 2)

		// Field: local_adddress.
		var localAddr linux.SockAddrInet
		if local, _, err := sops.GetSockName(t); err == nil {
			localAddr = *local.(*linux.SockAddrInet)
		}
		binary.LittleEndian.PutUint16(portBuf, localAddr.Port)
		fmt.Fprintf(buf, "%08X:%04X ",
			binary.LittleEndian.Uint32(localAddr.Addr[:]),
			portBuf)

		// Field: rem_address.
		var remoteAddr linux.SockAddrInet
		if remote, _, err := sops.GetPeerName(t); err == nil {
			remoteAddr = *remote.(*linux.SockAddrInet)
		}
		binary.LittleEndian.PutUint16(portBuf, remoteAddr.Port)
		fmt.Fprintf(buf, "%08X:%04X ",
			binary.LittleEndian.Uint32(remoteAddr.Addr[:]),
			portBuf)

		// Field: state; socket state.
		fmt.Fprintf(buf, "%02X ", sops.State())

		// Field: tx_queue, rx_queue; number of packets in the transmit and
		// receive queue. Unimplemented.
		fmt.Fprintf(buf, "%08X:%08X ", 0, 0)

		// Field: tr, tm->when; timer active state and number of jiffies
		// until timer expires. Unimplemented.
		fmt.Fprintf(buf, "%02X:%08X ", 0, 0)

		// Field: retrnsmt; number of unrecovered RTO timeouts.
		// Unimplemented.
		fmt.Fprintf(buf, "%08X ", 0)

		// Field: uid.
		uattr, err := sfile.Dirent.Inode.UnstableAttr(ctx)
		if err != nil {
			log.Warningf("Failed to retrieve unstable attr for socket file: %v", err)
			fmt.Fprintf(buf, "%5d ", 0)
		} else {
			fmt.Fprintf(buf, "%5d ", uint32(uattr.Owner.UID.In(t.UserNamespace()).OrOverflow()))
		}

		// Field: timeout; number of unanswered 0-window probes.
		// Unimplemented.
		fmt.Fprintf(buf, "%8d ", 0)

		// Field: inode.
		fmt.Fprintf(buf, "%8d ", sfile.InodeID())

		// Field: refcount. Don't count the ref we obtain while deferencing
		// the weakref to this socket.
		fmt.Fprintf(buf, "%d ", sfile.ReadRefs()-1)

		// Field: Socket struct address. Redacted due to the same reason as
		// the 'Num' field in /proc/net/unix, see netUnix.ReadSeqFileData.
		fmt.Fprintf(buf, "%#016p ", (*socket.Socket)(nil))

		// Field: retransmit timeout. Unimplemented.
		fmt.Fprintf(buf, "%d ", 0)

		// Field: predicted tick of soft clock (delayed ACK control data).
		// Unimplemented.
		fmt.Fprintf(buf, "%d ", 0)

		// Field: (ack.quick<<1)|ack.pingpong, Unimplemented.
		fmt.Fprintf(buf, "%d ", 0)

		// Field: sending congestion window, Unimplemented.
		fmt.Fprintf(buf, "%d ", 0)

		// Field: Slow start size threshold, -1 if threshold >= 0xFFFF.
		// Unimplemented, report as large threshold.
		fmt.Fprintf(buf, "%d", -1)

		fmt.Fprintf(buf, "\n")

		s.DecRef()
	}

	return nil
}
