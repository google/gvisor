// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dhcp

import (
	"bytes"
	"context"
	"crypto/rand"
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

// Client is a DHCP client.
type Client struct {
	stack    *stack.Stack
	nicid    tcpip.NICID
	linkAddr tcpip.LinkAddress

	mu          sync.Mutex
	addr        tcpip.Address
	cfg         Config
	lease       time.Duration
	cancelRenew func()
}

// NewClient creates a DHCP client.
//
// TODO: add s.LinkAddr(nicid) to *stack.Stack.
func NewClient(s *stack.Stack, nicid tcpip.NICID, linkAddr tcpip.LinkAddress) *Client {
	return &Client{
		stack:    s,
		nicid:    nicid,
		linkAddr: linkAddr,
	}
}

// Start starts the DHCP client.
// It will periodically search for an IP address using the Request method.
func (c *Client) Start() {
	go func() {
		for {
			log.Print("DHCP request")
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			err := c.Request(ctx, "")
			cancel()
			if err == nil {
				break
			}
		}
		log.Printf("DHCP acquired IP %s for %s", c.Address(), c.Config().LeaseLength)
	}()
}

// Address reports the IP address acquired by the DHCP client.
func (c *Client) Address() tcpip.Address {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.addr
}

// Config reports the DHCP configuration acquired with the IP address lease.
func (c *Client) Config() Config {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cfg
}

// Shutdown relinquishes any lease and ends any outstanding renewal timers.
func (c *Client) Shutdown() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.addr != "" {
		c.stack.RemoveAddress(c.nicid, c.addr)
	}
	if c.cancelRenew != nil {
		c.cancelRenew()
	}
}

// Request executes a DHCP request session.
//
// On success, it adds a new address to this client's TCPIP stack.
// If the server sets a lease limit a timer is set to automatically
// renew it.
func (c *Client) Request(ctx context.Context, requestedAddr tcpip.Address) error {
	var wq waiter.Queue
	ep, err := c.stack.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if err != nil {
		return fmt.Errorf("dhcp: outbound endpoint: %v", err)
	}
	err = ep.Bind(tcpip.FullAddress{
		Addr: "\x00\x00\x00\x00",
		Port: clientPort,
	}, nil)
	defer ep.Close()
	if err != nil {
		return fmt.Errorf("dhcp: connect failed: %v", err)
	}

	epin, err := c.stack.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if err != nil {
		return fmt.Errorf("dhcp: inbound endpoint: %v", err)
	}
	err = epin.Bind(tcpip.FullAddress{
		Addr: "\xff\xff\xff\xff",
		Port: clientPort,
	}, nil)
	defer epin.Close()
	if err != nil {
		return fmt.Errorf("dhcp: connect failed: %v", err)
	}

	var xid [4]byte
	rand.Read(xid[:])

	// DHCPDISCOVERY
	options := options{
		{optDHCPMsgType, []byte{byte(dhcpDISCOVER)}},
		{optParamReq, []byte{
			1,  // request subnet mask
			3,  // request router
			15, // domain name
			6,  // domain name server
		}},
	}
	if requestedAddr != "" {
		options = append(options, option{optReqIPAddr, []byte(requestedAddr)})
	}
	h := make(header, headerBaseSize+options.len())
	h.init()
	h.setOp(opRequest)
	copy(h.xidbytes(), xid[:])
	h.setBroadcast()
	copy(h.chaddr(), c.linkAddr)
	h.setOptions(options)

	serverAddr := &tcpip.FullAddress{
		Addr: "\xff\xff\xff\xff",
		Port: serverPort,
	}
	wopts := tcpip.WriteOptions{
		To: serverAddr,
	}
	if _, err := ep.Write(tcpip.SlicePayload(h), wopts); err != nil {
		return fmt.Errorf("dhcp discovery write: %v", err)
	}

	we, ch := waiter.NewChannelEntry(nil)
	wq.EventRegister(&we, waiter.EventIn)
	defer wq.EventUnregister(&we)

	// DHCPOFFER
	for {
		var addr tcpip.FullAddress
		v, _, err := epin.Read(&addr)
		if err == tcpip.ErrWouldBlock {
			select {
			case <-ch:
				continue
			case <-ctx.Done():
				return fmt.Errorf("reading dhcp offer: %v", tcpip.ErrAborted)
			}
		}
		h = header(v)
		if h.isValid() && h.op() == opReply && bytes.Equal(h.xidbytes(), xid[:]) {
			break
		}
	}
	if _, err := h.options(); err != nil {
		return fmt.Errorf("dhcp offer: %v", err)
	}

	var ack bool
	var cfg Config

	// DHCPREQUEST
	addr := tcpip.Address(h.yiaddr())
	if err := c.stack.AddAddress(c.nicid, ipv4.ProtocolNumber, addr); err != nil {
		if err != tcpip.ErrDuplicateAddress {
			return fmt.Errorf("adding address: %v", err)
		}
	}
	defer func() {
		if ack {
			c.mu.Lock()
			c.addr = addr
			c.cfg = cfg
			c.mu.Unlock()
		} else {
			c.stack.RemoveAddress(c.nicid, addr)
		}
	}()
	h.setOp(opRequest)
	for i, b := 0, h.yiaddr(); i < len(b); i++ {
		b[i] = 0
	}
	h.setOptions([]option{
		{optDHCPMsgType, []byte{byte(dhcpREQUEST)}},
		{optReqIPAddr, []byte(addr)},
		{optDHCPServer, h.siaddr()},
	})
	if _, err := ep.Write(tcpip.SlicePayload(h), wopts); err != nil {
		return fmt.Errorf("dhcp discovery write: %v", err)
	}

	// DHCPACK
	for {
		var addr tcpip.FullAddress
		v, _, err := epin.Read(&addr)
		if err == tcpip.ErrWouldBlock {
			select {
			case <-ch:
				continue
			case <-ctx.Done():
				return fmt.Errorf("reading dhcp ack: %v", tcpip.ErrAborted)
			}
		}
		h = header(v)
		if h.isValid() && h.op() == opReply && bytes.Equal(h.xidbytes(), xid[:]) {
			break
		}
	}
	opts, e := h.options()
	if e != nil {
		return fmt.Errorf("dhcp ack: %v", e)
	}
	if err := cfg.decode(opts); err != nil {
		return fmt.Errorf("dhcp ack bad options: %v", err)
	}
	msgtype, e := opts.dhcpMsgType()
	if e != nil {
		return fmt.Errorf("dhcp ack: %v", e)
	}
	ack = msgtype == dhcpACK
	if !ack {
		return fmt.Errorf("dhcp: request not acknowledged")
	}
	if cfg.LeaseLength != 0 {
		go c.renewAfter(cfg.LeaseLength)
	}
	return nil
}

func (c *Client) renewAfter(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cancelRenew != nil {
		c.cancelRenew()
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.cancelRenew = cancel
	go func() {
		timer := time.NewTimer(d)
		defer timer.Stop()
		select {
		case <-ctx.Done():
		case <-timer.C:
			if err := c.Request(ctx, c.addr); err != nil {
				log.Printf("address renewal failed: %v", err)
				go c.renewAfter(1 * time.Minute)
			}
		}
	}()
}
