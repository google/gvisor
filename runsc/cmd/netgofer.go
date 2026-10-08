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

package cmd

import (
	"context"
	"io"
	"net"
	"runtime/debug"
	"strconv"
	"sync"
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
	"gvisor.dev/gvisor/pkg/waiter"
	"gvisor.dev/gvisor/runsc/cmd/sandboxsetup"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/flag"
	egressfilter "gvisor.dev/gvisor/runsc/netgofer/egressfilter"
	netgoferfilter "gvisor.dev/gvisor/runsc/netgofer/filter"
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
// It runs a user-space netstack to proxy outbound TCP traffic and intercepts
// TCP traffic from sandbox and forwards it to the host network via host
// sockets (translating source IP to host/pod IP).
//
// Limitations:
//   - Only outbound TCP traffic is supported. UDP (including standard UDP-based DNS
//     queries), ICMP, and inbound connections are not supported.
//   - Network connection preservation across save/restore is not supported, existing
//     connections will be reset upon restore.
type Netgofer struct {
	util.InternalSubCommand

	udsFD          int
	mtu            int
	applyCaps      bool
	disableSeccomp bool
	maxActiveConns int
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
	f.IntVar(&n.mtu, "mtu", DefaultMTU, "MTU for the network interface")
	f.BoolVar(&n.applyCaps, "apply-caps", true, "if true, apply capabilities to restrict what the netgofer process can do")
	f.IntVar(&n.maxActiveConns, "max-active-conns", defaultMaxActiveConns, "maximum number of concurrent active connections")
	n.profileFDs.SetFromFlags(f)
}

// Execute implements subcommands.Command.
func (n *Netgofer) Execute(_ context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	if n.udsFD < 0 {
		if f.Usage != nil {
			f.Usage()
		}
		return subcommands.ExitUsageError
	}
	if f.NArg() != 1 {
		_ = unix.Close(n.udsFD)
		if f.Usage != nil {
			f.Usage()
		}
		return subcommands.ExitUsageError
	}
	sandboxID := f.Arg(0)

	if len(args) == 0 {
		_ = unix.Close(n.udsFD)
		return util.Errorf("missing config")
	}
	conf, ok := args[0].(*config.Config)
	if !ok {
		_ = unix.Close(n.udsFD)
		return util.Errorf("first argument must be *config.Config, got %T", args[0])
	}

	// Set traceback level.
	debug.SetTraceback(conf.Traceback)

	log.Infof("Starting netgofer for sandbox %q", sandboxID)

	if n.applyCaps {
		if config.CgoEnabled {
			log.Warningf("Need to re-exec in order to drop capabilities, due to cgo build. Use a pure-Go gVisor build to avoid this.")
			// Clear FD_CLOEXEC so udsFD survives re-exec.
			if _, _, errno := unix.RawSyscall(unix.SYS_FCNTL, uintptr(n.udsFD), unix.F_SETFD, 0); errno != 0 {
				_ = unix.Close(n.udsFD)
				return util.Errorf("error clearing CLOEXEC on udsFD: %v", errno)
			}
			reexecArgs := sandboxsetup.PrepareArgs(n.Name(), f, map[string]string{"apply-caps": "false"})
			util.Fatalf("setCapsAndCallSelf(%v, %v): %v", reexecArgs, netgoferCaps, sandboxsetup.SetCapsAndCallSelf(reexecArgs, netgoferCaps))
			panic("unreachable")
		}
		if err := sandboxsetup.ApplyCapsAllThreads(netgoferCaps, nil); err != nil {
			_ = unix.Close(n.udsFD)
			return util.Errorf("dropping capabilities: %v", err)
		}
	}

	profileOpts := profile.MakeOpts(&n.profileFDs, conf.ProfileGCInterval)
	n.profileEnabled = profileOpts.Enabled()
	stopProfiling := profile.Start(profileOpts)
	defer stopProfiling()

	// TODO(b/518947343): Add support to use passt.
	return n.runProxyMode(conf)
}

func (n *Netgofer) runProxyMode(conf *config.Config) subcommands.ExitStatus {
	log.Infof("Running in proxy mode")

	ctx, cancel := context.WithCancel(context.Background())
	var (
		wg         sync.WaitGroup
		wgMu       sync.Mutex
		stopping   bool
		linkEP     stack.LinkEndpoint
		linkEPDone bool
	)
	st := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
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
	var gsoMaxSize uint32 = stack.GVisorGSOMaxSize
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
		f, err := egressfilter.New(egressfilter.Options{})
		if err != nil {
			log.Warningf("Failed to initialize egress filter: %v", err)
			return subcommands.ExitFailure
		}
		n.egressFilter = f
	}

	// Add default routes and register the TCP forwarder before creating/attaching
	// the NIC so that packets arriving immediately upon NIC attachment are routed
	// to the forwarder.
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

	forwarder := tcp.NewForwarder(st, 0, maxInFlightConns, func(r *tcp.ForwarderRequest) {
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
	st.SetTransportProtocolHandler(tcp.ProtocolNumber, forwarder.HandlePacket)

	var (
		closeErrMu sync.Mutex
		closeErr   tcpip.Error
	)
	// fdbased.New must run before netgoferfilter.Install because it calls
	// fstat on the UDS FD, which is disallowed by the seccomp filter.
	var err error
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

	log.Infof("TCP forwarder registered")
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
