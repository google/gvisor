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

package dhcp

import (
	"context"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"gvisor.googlesource.com/gvisor/pkg/tcpip"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/buffer"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/stack"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/transport/udp"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
)

// Server is a DHCP server.
type Server struct {
	conn      conn
	broadcast tcpip.FullAddress
	addrs     []tcpip.Address // TODO: use a tcpip.AddressMask or range structure
	cfg       Config
	cfgopts   []option // cfg to send to client

	handlers []chan header

	mu     sync.Mutex
	leases map[tcpip.LinkAddress]serverLease
}

// conn is a blocking read/write network endpoint.
type conn interface {
	Read() (buffer.View, tcpip.FullAddress, error)
	Write([]byte, *tcpip.FullAddress) error
}

type epConn struct {
	ctx  context.Context
	wq   *waiter.Queue
	ep   tcpip.Endpoint
	we   waiter.Entry
	inCh chan struct{}
}

func newEPConn(ctx context.Context, wq *waiter.Queue, ep tcpip.Endpoint) *epConn {
	c := &epConn{
		ctx: ctx,
		wq:  wq,
		ep:  ep,
	}
	c.we, c.inCh = waiter.NewChannelEntry(nil)
	wq.EventRegister(&c.we, waiter.EventIn)

	go func() {
		<-ctx.Done()
		wq.EventUnregister(&c.we)
	}()

	return c
}

func (c *epConn) Read() (buffer.View, tcpip.FullAddress, error) {
	for {
		var addr tcpip.FullAddress
		v, _, err := c.ep.Read(&addr)
		if err == tcpip.ErrWouldBlock {
			select {
			case <-c.inCh:
				continue
			case <-c.ctx.Done():
				return nil, tcpip.FullAddress{}, io.EOF
			}
		}
		if err != nil {
			return v, addr, fmt.Errorf("read: %v", err)
		}
		return v, addr, nil
	}
}

func (c *epConn) Write(b []byte, addr *tcpip.FullAddress) error {
	_, resCh, err := c.ep.Write(tcpip.SlicePayload(b), tcpip.WriteOptions{To: addr})
	if err != nil && resCh == nil {
		return fmt.Errorf("write: %v", err)
	}

	if resCh != nil {
		select {
		case <-resCh:
		case <-c.ctx.Done():
			return fmt.Errorf("dhcp server address resolution: %v", tcpip.ErrAborted)
		}

		if _, _, err := c.ep.Write(tcpip.SlicePayload(b), tcpip.WriteOptions{To: addr}); err != nil {
			return fmt.Errorf("write: %v", err)
		}
	}
	return nil
}

func newEPConnServer(ctx context.Context, stack *stack.Stack, addrs []tcpip.Address, cfg Config) (*Server, error) {
	wq := new(waiter.Queue)
	ep, err := stack.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, wq)
	if err != nil {
		return nil, fmt.Errorf("dhcp: server endpoint: %v", err)
	}
	if err := ep.Bind(tcpip.FullAddress{Port: ServerPort}); err != nil {
		return nil, fmt.Errorf("dhcp: server bind: %v", err)
	}
	if err := ep.SetSockOpt(tcpip.BroadcastOption(1)); err != nil {
		return nil, fmt.Errorf("dhcp: server setsockopt: %v", err)
	}
	c := newEPConn(ctx, wq, ep)
	return NewServer(ctx, c, addrs, cfg)
}

// NewServer creates a new DHCP server and begins serving.
// The server continues serving until ctx is done.
func NewServer(ctx context.Context, c conn, addrs []tcpip.Address, cfg Config) (*Server, error) {
	if cfg.ServerAddress == "" {
		return nil, fmt.Errorf("dhcp: server requires explicit server address")
	}
	s := &Server{
		conn:    c,
		addrs:   addrs,
		cfg:     cfg,
		cfgopts: cfg.encode(),
		broadcast: tcpip.FullAddress{
			Addr: "\xff\xff\xff\xff",
			Port: ClientPort,
		},

		handlers: make([]chan header, 8),
		leases:   make(map[tcpip.LinkAddress]serverLease),
	}

	for i := 0; i < len(s.handlers); i++ {
		ch := make(chan header, 8)
		s.handlers[i] = ch
		go s.handler(ctx, ch)
	}

	go s.expirer(ctx)
	go s.reader(ctx)
	return s, nil
}

func (s *Server) expirer(ctx context.Context) {
	t := time.NewTicker(1 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			s.mu.Lock()
			for linkAddr, lease := range s.leases {
				if time.Since(lease.start) > s.cfg.LeaseLength {
					lease.state = leaseExpired
					s.leases[linkAddr] = lease
				}
			}
			s.mu.Unlock()
		case <-ctx.Done():
			return
		}
	}
}

// reader listens for all incoming DHCP packets and fans them out to
// handling goroutines based on XID as session identifiers.
func (s *Server) reader(ctx context.Context) {
	for {
		v, _, err := s.conn.Read()
		if err != nil {
			return
		}

		h := header(v)
		if !h.isValid() || h.op() != opRequest {
			continue
		}
		xid := h.xid()

		// Fan out the packet to a handler goroutine.
		//
		// Use a consistent handler for a given xid, so that
		// packets from a particular client are processed
		// in order.
		ch := s.handlers[int(xid)%len(s.handlers)]
		select {
		case <-ctx.Done():
			return
		case ch <- h:
		default:
			// drop the packet
		}
	}
}

func (s *Server) handler(ctx context.Context, ch chan header) {
	for {
		select {
		case h := <-ch:
			if h == nil {
				return
			}
			opts, err := h.options()
			if err != nil {
				continue
			}
			// TODO: Handle DHCPRELEASE and DHCPDECLINE.
			msgtype, err := opts.dhcpMsgType()
			if err != nil {
				continue
			}
			switch msgtype {
			case dhcpDISCOVER:
				s.handleDiscover(h, opts)
			case dhcpREQUEST:
				s.handleRequest(h, opts)
			}
		case <-ctx.Done():
			return
		}
	}
}

func (s *Server) handleDiscover(hreq header, opts options) {
	linkAddr := tcpip.LinkAddress(hreq.chaddr()[:6])
	xid := hreq.xid()

	s.mu.Lock()
	lease := s.leases[linkAddr]
	switch lease.state {
	case leaseNew:
		if len(s.leases) < len(s.addrs) {
			// Find an unused address.
			// TODO: avoid building this state on each request.
			alloced := make(map[tcpip.Address]bool)
			for _, lease := range s.leases {
				alloced[lease.addr] = true
			}
			for _, addr := range s.addrs {
				if !alloced[addr] {
					lease = serverLease{
						start: time.Now(),
						addr:  addr,
						xid:   xid,
						state: leaseOffer,
					}
					s.leases[linkAddr] = lease
					break
				}
			}
		} else {
			// No more addresses, take an expired address.
			for k, oldLease := range s.leases {
				if oldLease.state == leaseExpired {
					delete(s.leases, k)
					lease = serverLease{
						start: time.Now(),
						addr:  lease.addr,
						xid:   xid,
						state: leaseOffer,
					}
					s.leases[linkAddr] = lease
					break
				}
			}
			log.Printf("server has no more addresses")
			s.mu.Unlock()
			return
		}
	case leaseOffer, leaseAck, leaseExpired:
		lease = serverLease{
			start: time.Now(),
			addr:  s.leases[linkAddr].addr,
			xid:   xid,
			state: leaseOffer,
		}
		s.leases[linkAddr] = lease
	}
	s.mu.Unlock()

	// DHCPOFFER
	opts = options{{optDHCPMsgType, []byte{byte(dhcpOFFER)}}}
	opts = append(opts, s.cfgopts...)
	h := make(header, headerBaseSize+opts.len()+1)
	h.init()
	h.setOp(opReply)
	copy(h.xidbytes(), hreq.xidbytes())
	copy(h.yiaddr(), lease.addr)
	copy(h.chaddr(), hreq.chaddr())
	h.setOptions(opts)
	s.conn.Write([]byte(h), &s.broadcast)
}

func (s *Server) nack(hreq header) {
	// DHCPNACK
	opts := options([]option{
		{optDHCPMsgType, []byte{byte(dhcpNAK)}},
		{optDHCPServer, []byte(s.cfg.ServerAddress)},
	})
	h := make(header, headerBaseSize+opts.len()+1)
	h.init()
	h.setOp(opReply)
	copy(h.xidbytes(), hreq.xidbytes())
	copy(h.chaddr(), hreq.chaddr())
	h.setOptions(opts)
	s.conn.Write([]byte(h), &s.broadcast)
}

func (s *Server) handleRequest(hreq header, opts options) {
	linkAddr := tcpip.LinkAddress(hreq.chaddr()[:6])
	xid := hreq.xid()

	reqopts, err := hreq.options()
	if err != nil {
		s.nack(hreq)
		return
	}
	var reqcfg Config
	if err := reqcfg.decode(reqopts); err != nil {
		s.nack(hreq)
		return
	}
	if reqcfg.ServerAddress != s.cfg.ServerAddress {
		// This request is for a different DHCP server. Ignore it.
		return
	}

	s.mu.Lock()
	lease := s.leases[linkAddr]
	switch lease.state {
	case leaseOffer, leaseAck, leaseExpired:
		lease = serverLease{
			start: time.Now(),
			addr:  s.leases[linkAddr].addr,
			xid:   xid,
			state: leaseAck,
		}
		s.leases[linkAddr] = lease
	}
	s.mu.Unlock()

	if lease.state == leaseNew {
		// TODO: NACK or accept request
		return
	}

	// DHCPACK
	opts = []option{{optDHCPMsgType, []byte{byte(dhcpACK)}}}
	opts = append(opts, s.cfgopts...)
	h := make(header, headerBaseSize+opts.len()+1)
	h.init()
	h.setOp(opReply)
	copy(h.xidbytes(), hreq.xidbytes())
	copy(h.yiaddr(), lease.addr)
	copy(h.chaddr(), hreq.chaddr())
	h.setOptions(opts)
	s.conn.Write([]byte(h), &s.broadcast)
}

type leaseState int

const (
	leaseNew leaseState = iota
	leaseOffer
	leaseAck
	leaseExpired
)

type serverLease struct {
	start time.Time
	addr  tcpip.Address
	xid   xid
	state leaseState
}
