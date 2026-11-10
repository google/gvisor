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

// Package net implements the netgofer sidecar network proxy.
package net

import (
	"context"
	"io"
	"net"
	"runtime/debug"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/google/subcommands"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
	"gvisor.dev/gvisor/runsc/cmd/sandboxsetup"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/flag"
	egressfilter "gvisor.dev/gvisor/runsc/gofer/net/egressfilter"
	netgoferfilter "gvisor.dev/gvisor/runsc/gofer/net/filter"
	"gvisor.dev/gvisor/runsc/profile"
)

const (
	// DefaultMTU is the MTU assumed for a network link when none is otherwise
	// known. It matches the conventional Ethernet MTU.
	DefaultMTU = 1500

	// keepAlivePeriod is the TCP keepalive interval applied to proxied host
	// connections for the peer to send FIN/RST before disappearing.
	keepAlivePeriod = 30 * time.Second

	defaultDialTimeout                = 30 * time.Second
	defaultUDPIdleTimeout             = 30 * time.Second
	maxUDPDatagramSize                = 65535
	defaultMaxActiveConns             = 4096
	defaultNICID          tcpip.NICID = 1
	maxInFlightConns                  = 10000
)

var netgoferCaps = &specs.LinuxCapabilities{}

// Netgofer implements subcommands.Command for the "netgofer" command.
//
// netgofer acts as a network proxy for gVisor sandboxes (runsc)
// to proxy network traffic over a unix domain socket (UDS) connection. It
// should not be called directly.
//
// It runs a user-space netstack to proxy outbound TCP and UDP traffic and
// intercepts traffic from the sandbox and forwards it to the host network via
// host sockets (translating source IP to host/pod IP).
//
// If --passt-fd is set, netgofer runs in passt mode instead: it copies packets
// between the sandbox and a passt process, which opens the host sockets. See
// passt.go.
//
// Limitations:
//   - Only outbound TCP and UDP traffic is supported. ICMP and inbound
//     connections are not supported.
//   - Link-local destinations (169.254.0.0/16 and fe80::/10, including GCE
//     metadata DNS 169.254.169.254 and NodeLocal DNSCache 169.254.20.10) are
//     blocked by the egress filter.
//   - Network connection preservation across save/restore is not supported, existing
//     connections will be reset upon restore.
type Netgofer struct {
	util.InternalSubCommand

	udsFD          int
	passtFD        int
	mtu            int
	applyCaps      bool
	allowLoopback  bool
	disableSeccomp bool
	maxActiveConns int
	udpIdleTimeout time.Duration
	activeConns    chan struct{}
	egressFilter   *egressfilter.Filter
	ready          chan struct{}
	dialContext    func(ctx context.Context, network, addr string) (net.Conn, error)
	profileFDs     profile.FDArgs
	profileEnabled bool
}

// Name implements subcommands.Command.
func (*Netgofer) Name() string {
	return "netgofer"
}

// Synopsis implements subcommands.Command.
func (*Netgofer) Synopsis() string {
	return "launch a netgofer process that proxies network traffic for all containers in the sandbox"
}

// Usage implements subcommands.Command.
func (*Netgofer) Usage() string {
	return "netgofer [flags] <sandbox ID>\n"
}

// SetFlags implements subcommands.Command.
func (n *Netgofer) SetFlags(f *flag.FlagSet) {
	f.IntVar(&n.udsFD, "uds-fd", -1, "FD of the host side UDS")
	f.IntVar(&n.passtFD, "passt-fd", -1, "FD of a connected SOCK_STREAM socket to passt. If set, netgofer runs in passt mode")
	f.IntVar(&n.mtu, "mtu", DefaultMTU, "MTU for the network interface")
	f.BoolVar(&n.applyCaps, "apply-caps", true, "if true, apply capabilities to restrict what the netgofer process can do")
	f.IntVar(&n.maxActiveConns, "max-active-conns", defaultMaxActiveConns, "maximum number of concurrent active connections")
	n.profileFDs.SetFromFlags(f)
	f.BoolVar(&n.allowLoopback, "allow-loopback", false, "if true, allow forwarding traffic destined to loopback addresses in the netgofer network namespace")
}

// Execute implements subcommands.Command.
func (n *Netgofer) Execute(_ context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	if n.udsFD < 0 {
		n.closeFDs()
		if f.Usage != nil {
			f.Usage()
		}
		return subcommands.ExitUsageError
	}
	if f.NArg() != 1 {
		n.closeFDs()
		if f.Usage != nil {
			f.Usage()
		}
		return subcommands.ExitUsageError
	}
	sandboxID := f.Arg(0)

	if len(args) == 0 {
		n.closeFDs()
		return util.Errorf("missing config")
	}
	conf, ok := args[0].(*config.Config)
	if !ok {
		n.closeFDs()
		return util.Errorf("first argument must be *config.Config, got %T", args[0])
	}

	// Set traceback level.
	debug.SetTraceback(conf.Traceback)

	log.Infof("Starting netgofer for sandbox %q", sandboxID)

	if n.applyCaps {
		if config.CgoEnabled {
			log.Warningf("Need to re-exec in order to drop capabilities, due to cgo build. Use a pure-Go gVisor build to avoid this.")
			// Clear FD_CLOEXEC so udsFD and passtFD survive re-exec.
			if _, _, errno := unix.RawSyscall(unix.SYS_FCNTL, uintptr(n.udsFD), unix.F_SETFD, 0); errno != 0 {
				n.closeFDs()
				return util.Errorf("error clearing CLOEXEC on udsFD: %v", errno)
			}
			if n.passtFD >= 0 {
				if _, _, errno := unix.RawSyscall(unix.SYS_FCNTL, uintptr(n.passtFD), unix.F_SETFD, 0); errno != 0 {
					n.closeFDs()
					return util.Errorf("error clearing CLOEXEC on passtFD: %v", errno)
				}
			}
			reexecArgs := sandboxsetup.PrepareArgs(n.Name(), f, map[string]string{"apply-caps": "false"})
			util.Fatalf("setCapsAndCallSelf(%v, %v): %v", reexecArgs, netgoferCaps, sandboxsetup.SetCapsAndCallSelf(reexecArgs, netgoferCaps))
			panic("unreachable")
		}
		if err := sandboxsetup.ApplyCapsAllThreads(netgoferCaps, nil); err != nil {
			n.closeFDs()
			return util.Errorf("dropping capabilities: %v", err)
		}
	}

	profileOpts := profile.MakeOpts(&n.profileFDs, conf.ProfileGCInterval)
	n.profileEnabled = profileOpts.Enabled()
	stopProfiling := profile.Start(profileOpts)
	defer stopProfiling()

	if n.passtFD >= 0 {
		return n.runPasstMode(conf)
	}
	return n.runProxyMode(conf)
}

// closeFDs closes the FDs that netgofer received from runsc. Execute calls it
// on error paths before the FDs are handed to a run mode.
func (n *Netgofer) closeFDs() {
	if n.udsFD >= 0 {
		_ = unix.Close(n.udsFD)
	}
	if n.passtFD >= 0 {
		_ = unix.Close(n.passtFD)
	}
}

func (n *Netgofer) runProxyMode(conf *config.Config) subcommands.ExitStatus {
	if conf.Netgofer.AllowLoopback() {
		n.allowLoopback = true
	}
	log.Infof("Running in proxy mode (allowLoopback=%v)", n.allowLoopback)

	ctx, cancel := context.WithCancel(context.Background())
	var (
		wg         sync.WaitGroup
		wgMu       sync.Mutex
		stopping   bool
		linkEP     stack.LinkEndpoint
		linkEPDone bool
	)
	allowLoopback := n.allowLoopback
	st := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocolWithOptions(ipv4.Options{
				AllowExternalLoopbackTraffic: allowLoopback,
			}),
			ipv6.NewProtocolWithOptions(ipv6.Options{
				AllowExternalLoopbackTraffic: allowLoopback,
			}),
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
		},
	})
	defer func() {
		if linkEP != nil && !linkEPDone {
			linkEP.Close()
			linkEP.Wait()
		}
		wgMu.Lock()
		stopping = true
		wgMu.Unlock()
		cancel()
		st.Close()
		wg.Wait()
		st.Wait()
		_ = unix.Close(n.udsFD)
	}()

	if n.mtu <= 0 {
		n.mtu = DefaultMTU
	}
	mtu := uint32(n.mtu)

	gvisorGSO := conf.GVisorGSO
	var gsoMaxSize uint32 = tcpip.GVisorGSOMaxSize
	if !gvisorGSO {
		gsoMaxSize = 0
	}
	txChecksumOffload := conf.TXChecksumOffload
	rxChecksumOffload := conf.RXChecksumOffload
	gvisorGRO := conf.GVisorGRO
	if txChecksumOffload {
		rxChecksumOffload = true
	}

	// Query local interface addresses and initialize the egress filter before
	// installing seccomp filters (which disallow netlink sockets) so
	// proxyOutboundRequest can reject connections targeting netgofer's own
	// network namespace IPs.
	if n.egressFilter == nil {
		f, err := egressfilter.New(egressfilter.Options{
			AllowLoopback: n.allowLoopback,
		})
		if err != nil {
			log.Warningf("Failed to initialize egress filter: %v", err)
			return subcommands.ExitFailure
		}
		n.egressFilter = f
	}

	// Add default routes and register the TCP and UDP forwarders before
	// creating/attaching the NIC so that packets arriving immediately upon NIC
	// attachment are routed to the forwarders.
	st.SetRouteTable([]tcpip.Route{
		{
			Destination: header.IPv4EmptySubnet,
			NIC:         defaultNICID,
		},
		{
			Destination: header.IPv6EmptySubnet,
			NIC:         defaultNICID,
		},
	})

	maxActive := n.maxActiveConns
	if maxActive <= 0 {
		maxActive = defaultMaxActiveConns
	}
	n.activeConns = make(chan struct{}, maxActive)

	tcpForwarder := tcp.NewForwarder(st, 0, maxInFlightConns, func(r *tcp.ForwarderRequest) {
		wgMu.Lock()
		if stopping {
			wgMu.Unlock()
			r.Complete(true)
			return
		}
		wg.Add(1)
		wgMu.Unlock()
		defer wg.Done()
		n.proxyOutboundRequest(ctx, r)
	})
	st.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)

	udpRejectLog := log.BasicRateLimitedLogger(time.Minute)
	udpForwarder := udp.NewForwarder(st, func(r *udp.ForwarderRequest) bool {
		return n.handleOutboundUDPRequest(ctx, &wg, &wgMu, &stopping, udpRejectLog, r)
	})
	st.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)

	var (
		closeErrMu sync.Mutex
		closeErr   tcpip.Error
	)
	// fdbased.New must run before netgoferfilter.Install because it calls
	// fstat on the UDS FD, which is disallowed by the seccomp filter.
	var err error
	// TODO(b/518947343): After the sentry closes its end of the UDS,
	// recvmmsg returns zero-length messages instead of EAGAIN, so the
	// RecvMMsg dispatcher below spins instead of exiting. Fix this by
	// making fdbased's recvMMsgDispatcher treat a zero-length message as
	// EOF, which keeps RecvMMsg batching.
	linkEP, err = fdbased.New(&fdbased.Options{
		FDs:                []int{n.udsFD},
		MTU:                mtu,
		EthernetHeader:     false, // IP-only packets over UDS
		PacketDispatchMode: fdbased.RecvMMsg,
		GSOMaxSize:         gsoMaxSize,
		GVisorGSOEnabled:   gvisorGSO,
		TXChecksumOffload:  txChecksumOffload,
		RXChecksumOffload:  rxChecksumOffload,
		GRO:                gvisorGRO,
		ClosedFunc: func(err tcpip.Error) {
			closeErrMu.Lock()
			defer closeErrMu.Unlock()
			closeErr = err
		},
	})
	if err != nil {
		log.Warningf("Failed to create fdbased LinkEndpoint: %v", err)
		return subcommands.ExitFailure
	}

	if !n.disableSeccomp {
		if err := netgoferfilter.Install(netgoferfilter.Options{
			ProfileEnabled: conf.ProfileEnable || n.profileEnabled,
			CgoEnabled:     config.CgoEnabled,
		}); err != nil {
			log.Warningf("Failed to install seccomp filters: %v", err)
			return subcommands.ExitFailure
		}
	}

	if err := st.CreateNIC(defaultNICID, linkEP); err != nil {
		log.Warningf("Failed to CreateNIC: %v", err)
		return subcommands.ExitFailure
	}

	// Enable address spoofing so that the NIC can send packets from any source
	// address (required to reply to sentry with the original destination IP).
	if err := st.SetSpoofing(defaultNICID, true); err != nil {
		log.Warningf("Failed to SetSpoofing: %v", err)
		return subcommands.ExitFailure
	}

	// Enable promiscuous mode so that the stack accepts all packets
	// destined for external IPs, allowing the Forwarders to intercept them.
	if err := st.SetPromiscuousMode(defaultNICID, true); err != nil {
		log.Warningf("Failed to SetPromiscuousMode: %v", err)
		return subcommands.ExitFailure
	}

	log.Infof("TCP and UDP forwarders registered")
	if n.ready != nil {
		close(n.ready)
	}

	linkEP.Wait()
	linkEPDone = true
	closeErrMu.Lock()
	linkErr := closeErr
	closeErrMu.Unlock()
	if linkErr != nil {
		switch linkErr.(type) {
		case *tcpip.ErrConnectionReset, *tcpip.ErrClosedForReceive:
			// Normal peer disconnect when the sandbox closes its end of the
			// SOCK_SEQPACKET UDS socket (POLLHUP -> ECONNRESET).
		default:
			log.Warningf("UDS link endpoint closed with error: %v", linkErr)
			return subcommands.ExitFailure
		}
	}
	log.Infof("UDS socket peer closed (Sandbox exited). Proxy exiting...")
	return subcommands.ExitSuccess
}

// proxyOutboundRequest forwards a single intercepted TCP connection from the
// sandbox to the host network.
//
// Source IP preservation for outbound traffic: when forwarding outbound traffic
// to the host (via net.Dial), the original source IP of the sandbox is NOT
// preserved. Instead, the host kernel assigns the source IP of the interface
// used to route the traffic.
//
// If netgofer is running in the pod's network namespace, this source IP will
// naturally be the pod's IP. If the sandbox is also configured to use actual
// pod IP (instead of a dummy IP like 10.0.0.2), then the source IP is
// effectively "preserved" from the network's perspective because both sentry
// and the host kernel use the same pod IP.
func (n *Netgofer) proxyOutboundRequest(ctx context.Context, r *tcp.ForwarderRequest) {
	id := r.ID()
	originalDst := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))
	log.Debugf("Connection target: %q", originalDst)

	if !n.egressFilter.Allows(id.LocalAddress, id.LocalPort) {
		log.Warningf("Rejecting connection to disallowed destination %q", originalDst)
		r.Complete(true)
		return
	}

	select {
	case n.activeConns <- struct{}{}:
		defer func() { <-n.activeConns }()
	default:
		log.Warningf("Rejecting connection to %q: max active connections (%d) reached", originalDst, cap(n.activeConns))
		r.Complete(true)
		return
	}

	dial := n.dialContext
	if dial == nil {
		dialer := net.Dialer{
			Timeout:   defaultDialTimeout,
			KeepAlive: keepAlivePeriod,
		}
		dial = dialer.DialContext
	}
	// Netgofer to host connection.
	hostConn, err := dial(ctx, "tcp", originalDst)
	if err != nil {
		log.Warningf("Failed to dial dynamic target %q: %v", originalDst, err)
		r.Complete(true)
		return
	}
	defer hostConn.Close()

	// Sandbox to netgofer connection.
	var wq waiter.Queue
	ep, eperr := r.CreateEndpoint(&wq)
	if eperr != nil {
		log.Warningf("Failed to create endpoint for target %q: %v", originalDst, eperr)
		r.Complete(true)
		return
	}
	r.Complete(false)
	c := gonet.NewTCPConn(&wq, ep)
	defer c.Close()

	// Ensure both sides of the proxied connection are closed immediately if
	// runProxyMode shuts down while splice is blocked on an idle hostConn.Read.
	stopCancel := context.AfterFunc(ctx, func() {
		_ = c.Close()
		_ = hostConn.Close()
	})
	defer stopCancel()

	log.Debugf("Dynamically forwarding TCP stream to: %q", originalDst)
	splice(c, hostConn)
	log.Debugf("Dynamic forwarding stream completed")
}

func (n *Netgofer) handleOutboundUDPRequest(ctx context.Context, wg *sync.WaitGroup, wgMu *sync.Mutex, stopping *bool, rejectLog log.Logger, r *udp.ForwarderRequest) bool {
	id := r.ID()
	originalDst := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))
	if log.IsLogging(log.Debug) {
		log.Debugf("UDP target: %q", originalDst)
	}

	if !n.egressFilter.Allows(id.LocalAddress, id.LocalPort) {
		rejectLog.Warningf("Rejecting UDP datagram to disallowed destination %q", originalDst)
		return false
	}

	wgMu.Lock()
	if *stopping {
		wgMu.Unlock()
		return false
	}
	select {
	case n.activeConns <- struct{}{}:
	default:
		wgMu.Unlock()
		rejectLog.Warningf("Rejecting UDP flow to %q: max active connections (%d) reached", originalDst, cap(n.activeConns))
		return false
	}
	var wq waiter.Queue
	ep, eperr := r.CreateEndpoint(&wq)
	if eperr != nil {
		<-n.activeConns
		wgMu.Unlock()
		rejectLog.Warningf("Failed to create UDP endpoint for target %q: %v", originalDst, eperr)
		return false
	}
	wg.Add(1)
	wgMu.Unlock()

	c := gonet.NewUDPConn(&wq, ep)
	go func() {
		defer wg.Done()
		defer func() { <-n.activeConns }()
		defer c.Close()
		n.proxyOutboundUDP(ctx, c, originalDst)
	}()
	return true
}

func disableUDPBroadcastControl(_, _ string, c syscall.RawConn) error {
	var sockoptErr error
	if err := c.Control(func(fd uintptr) {
		sockoptErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_BROADCAST, 0)
	}); err != nil {
		return err
	}
	return sockoptErr
}

func newOutboundUDPDialer() net.Dialer {
	return net.Dialer{
		Timeout: defaultDialTimeout,
		Control: disableUDPBroadcastControl,
	}
}

func (n *Netgofer) proxyOutboundUDP(ctx context.Context, c *gonet.UDPConn, originalDst string) {
	dial := n.dialContext
	if dial == nil {
		dialer := newOutboundUDPDialer()
		dial = dialer.DialContext
	}
	hostConn, err := dial(ctx, "udp", originalDst)
	if err != nil {
		log.Warningf("Failed to dial UDP target %q: %v", originalDst, err)
		return
	}
	defer hostConn.Close()

	stopCancel := context.AfterFunc(ctx, func() {
		_ = c.Close()
		_ = hostConn.Close()
	})
	defer stopCancel()

	idleTimeout := n.udpIdleTimeout
	if idleTimeout <= 0 {
		idleTimeout = defaultUDPIdleTimeout
	}

	log.Debugf("Dynamically forwarding UDP datagrams to: %q", originalDst)
	spliceUDP(c, hostConn, idleTimeout)
	log.Debugf("Dynamic UDP forwarding completed for: %q", originalDst)
}

var udpBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, maxUDPDatagramSize)
		return &buf
	},
}

func spliceUDP(c1, c2 net.Conn, idleTimeout time.Duration) {
	var (
		mu           sync.Mutex
		lastDeadline time.Time
	)
	refreshDeadlines := func(force bool) {
		now := time.Now()
		mu.Lock()
		if !force && lastDeadline.Sub(now) >= idleTimeout/2 {
			mu.Unlock()
			return
		}
		deadline := now.Add(idleTimeout)
		lastDeadline = deadline
		mu.Unlock()
		_ = c1.SetReadDeadline(deadline)
		_ = c2.SetReadDeadline(deadline)
	}
	refreshDeadlines(true)

	copyDatagrams := func(dst, src net.Conn) {
		bufPtr := udpBufPool.Get().(*[]byte)
		defer udpBufPool.Put(bufPtr)
		buf := *bufPtr
		for {
			nr, err := src.Read(buf)
			if nr > 0 || err == nil {
				refreshDeadlines(false)
				if _, werr := dst.Write(buf[:nr]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		_ = dst.Close()
		_ = src.Close()
	}

	done := make(chan struct{})
	go func() {
		copyDatagrams(c2, c1)
		close(done)
	}()
	copyDatagrams(c1, c2)
	<-done
	_ = c1.SetReadDeadline(time.Time{})
	_ = c2.SetReadDeadline(time.Time{})
}

type closeWriter interface {
	CloseWrite() error
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(closeWriter); ok {
		_ = cw.CloseWrite()
	} else {
		_ = c.Close()
	}
}

// splice copies data bidirectionally, propagating TCP half-close when
// one direction reaches EOF and closing both sockets when one direction
// terminates with an error or both complete. Each proxied connection
// uses 2 goroutines (incoming and outgoing traffic).
func splice(c1, c2 net.Conn) {
	copyOneWay := func(dst, src net.Conn) {
		_, err := io.Copy(dst, src)
		if err != nil {
			_ = dst.Close()
			_ = src.Close()
			return
		}
		closeWrite(dst)
	}
	done := make(chan struct{})
	go func() {
		copyOneWay(c2, c1)
		close(done)
	}()
	copyOneWay(c1, c2)
	<-done
	_ = c1.Close()
	_ = c2.Close()
}
