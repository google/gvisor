// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dhcp

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"gvisor.googlesource.com/gvisor/pkg/tcpip"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/stack"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/transport/udp"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
)

// Server is a DHCP server.
type Server struct {
	stack     *stack.Stack
	broadcast tcpip.FullAddress
	wq        waiter.Queue
	ep        tcpip.Endpoint
	addrs     []tcpip.Address // TODO: use a tcpip.AddressMask or range structure
	cfg       Config
	cfgopts   []option // cfg to send to client

	handlers []chan header

	mu     sync.Mutex
	leases map[tcpip.LinkAddress]serverLease
}

// NewServer creates a new DHCP server and begins serving.
// The server continues serving until ctx is done.
func NewServer(ctx context.Context, stack *stack.Stack, addrs []tcpip.Address, cfg Config) (*Server, error) {
	s := &Server{
		stack:   stack,
		addrs:   addrs,
		cfg:     cfg,
		cfgopts: cfg.encode(),
		broadcast: tcpip.FullAddress{
			Addr: "\xff\xff\xff\xff",
			Port: clientPort,
		},

		handlers: make([]chan header, 8),
		leases:   make(map[tcpip.LinkAddress]serverLease),
	}

	var err *tcpip.Error
	s.ep, err = s.stack.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &s.wq)
	if err != nil {
		return nil, fmt.Errorf("dhcp: server endpoint: %v", err)
	}
	serverBroadcast := tcpip.FullAddress{
		Addr: "",
		Port: serverPort,
	}
	if err := s.ep.Bind(serverBroadcast, nil); err != nil {
		return nil, fmt.Errorf("dhcp: server bind: %v", err)
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
	we, ch := waiter.NewChannelEntry(nil)
	s.wq.EventRegister(&we, waiter.EventIn)
	defer s.wq.EventUnregister(&we)

	for {
		var addr tcpip.FullAddress
		v, err := s.ep.Read(&addr)
		if err == tcpip.ErrWouldBlock {
			select {
			case <-ch:
				continue
			case <-ctx.Done():
				return
			}
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
	h := make(header, headerBaseSize+opts.len())
	h.init()
	h.setOp(opReply)
	copy(h.xidbytes(), hreq.xidbytes())
	copy(h.yiaddr(), lease.addr)
	copy(h.siaddr(), s.cfg.ServerAddress)
	copy(h.chaddr(), hreq.chaddr())
	h.setOptions(opts)
	s.ep.Write(tcpip.SlicePayload(h), tcpip.WriteOptions{To: &s.broadcast})
}

func (s *Server) handleRequest(hreq header, opts options) {
	linkAddr := tcpip.LinkAddress(hreq.chaddr()[:6])
	xid := hreq.xid()

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
	h := make(header, headerBaseSize+opts.len())
	h.init()
	h.setOp(opReply)
	copy(h.xidbytes(), hreq.xidbytes())
	copy(h.yiaddr(), lease.addr)
	copy(h.siaddr(), s.cfg.ServerAddress)
	copy(h.chaddr(), hreq.chaddr())
	h.setOptions(opts)
	s.ep.Write(tcpip.SlicePayload(h), tcpip.WriteOptions{To: &s.broadcast})
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
