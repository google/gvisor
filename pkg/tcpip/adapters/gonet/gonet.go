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

// Package gonet provides a Go net package compatible wrapper for a tcpip stack.
package gonet

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

var (
	errCanceled   = errors.New("operation canceled")
	errWouldBlock = errors.New("operation would block")
)

// timeoutError is how the net package reports timeouts.
type timeoutError struct{}

func (e *timeoutError) Error() string   { return "i/o timeout" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }

// A Listener is a wrapper around a tcpip endpoint that implements
// net.Listener.
type Listener struct {
	stack  *stack.Stack
	ep     tcpip.Endpoint
	wq     *waiter.Queue
	cancel chan struct{}
}

// NewListener creates a new Listener.
func NewListener(s *stack.Stack, addr tcpip.FullAddress, network tcpip.NetworkProtocolNumber) (*Listener, error) {
	// Create TCP endpoint, bind it, then start listening.
	var wq waiter.Queue
	ep, err := s.NewEndpoint(tcp.ProtocolNumber, network, &wq)
	if err != nil {
		return nil, errors.New(err.String())
	}

	if err := ep.Bind(addr); err != nil {
		ep.Close()
		return nil, &net.OpError{
			Op:   "bind",
			Net:  "tcp",
			Addr: fullToTCPAddr(addr),
			Err:  errors.New(err.String()),
		}
	}

	if err := ep.Listen(10); err != nil {
		ep.Close()
		return nil, &net.OpError{
			Op:   "listen",
			Net:  "tcp",
			Addr: fullToTCPAddr(addr),
			Err:  errors.New(err.String()),
		}
	}

	return &Listener{
		stack:  s,
		ep:     ep,
		wq:     &wq,
		cancel: make(chan struct{}),
	}, nil
}

// Close implements net.Listener.Close.
func (l *Listener) Close() error {
	l.ep.Close()
	return nil
}

// Shutdown stops the HTTP server.
func (l *Listener) Shutdown() {
	l.ep.Shutdown(tcpip.ShutdownWrite | tcpip.ShutdownRead)
	close(l.cancel) // broadcast cancellation
}

// Addr implements net.Listener.Addr.
func (l *Listener) Addr() net.Addr {
	a, err := l.ep.GetLocalAddress()
	if err != nil {
		return nil
	}
	return fullToTCPAddr(a)
}

type deadlineTimer struct {
	// mu protects the fields below.
	mu sync.Mutex

	readTimer     *time.Timer
	readCancelCh  chan struct{}
	writeTimer    *time.Timer
	writeCancelCh chan struct{}
}

func (d *deadlineTimer) init() {
	d.readCancelCh = make(chan struct{})
	d.writeCancelCh = make(chan struct{})
}

func (d *deadlineTimer) readCancel() <-chan struct{} {
	d.mu.Lock()
	c := d.readCancelCh
	d.mu.Unlock()
	return c
}
func (d *deadlineTimer) writeCancel() <-chan struct{} {
	d.mu.Lock()
	c := d.writeCancelCh
	d.mu.Unlock()
	return c
}

// setDeadline contains the shared logic for setting a deadline.
//
// cancelCh and timer must be pointers to deadlineTimer.readCancelCh and
// deadlineTimer.readTimer or deadlineTimer.writeCancelCh and
// deadlineTimer.writeTimer.
//
// setDeadline must only be called while holding d.mu.
func (d *deadlineTimer) setDeadline(cancelCh *chan struct{}, timer **time.Timer, t time.Time) {
	if *timer != nil && !(*timer).Stop() {
		*cancelCh = make(chan struct{})
	}

	// Create a new channel if we already closed it due to setting an already
	// expired time. We won't race with the timer because we already handled
	// that above.
	select {
	case <-*cancelCh:
		*cancelCh = make(chan struct{})
	default:
	}

	// "A zero value for t means I/O operations will not time out."
	// - net.Conn.SetDeadline
	if t.IsZero() {
		return
	}

	timeout := t.Sub(time.Now())
	if timeout <= 0 {
		close(*cancelCh)
		return
	}

	// Timer.Stop returns whether or not the AfterFunc has started, but
	// does not indicate whether or not it has completed. Make a copy of
	// the cancel channel to prevent this code from racing with the next
	// call of setDeadline replacing *cancelCh.
	ch := *cancelCh
	*timer = time.AfterFunc(timeout, func() {
		close(ch)
	})
}

// SetReadDeadline implements net.Conn.SetReadDeadline and
// net.PacketConn.SetReadDeadline.
func (d *deadlineTimer) SetReadDeadline(t time.Time) error {
	d.mu.Lock()
	d.setDeadline(&d.readCancelCh, &d.readTimer, t)
	d.mu.Unlock()
	return nil
}

// SetWriteDeadline implements net.Conn.SetWriteDeadline and
// net.PacketConn.SetWriteDeadline.
func (d *deadlineTimer) SetWriteDeadline(t time.Time) error {
	d.mu.Lock()
	d.setDeadline(&d.writeCancelCh, &d.writeTimer, t)
	d.mu.Unlock()
	return nil
}

// SetDeadline implements net.Conn.SetDeadline and net.PacketConn.SetDeadline.
func (d *deadlineTimer) SetDeadline(t time.Time) error {
	d.mu.Lock()
	d.setDeadline(&d.readCancelCh, &d.readTimer, t)
	d.setDeadline(&d.writeCancelCh, &d.writeTimer, t)
	d.mu.Unlock()
	return nil
}

// A Conn is a wrapper around a tcpip.Endpoint that implements the net.Conn
// interface.
type Conn struct {
	deadlineTimer

	wq *waiter.Queue
	ep tcpip.Endpoint

	// readMu serializes reads and implicitly protects read.
	//
	// Lock ordering:
	// If both readMu and deadlineTimer.mu are to be used in a single
	// request, readMu must be acquired before deadlineTimer.mu.
	readMu sync.Mutex

	// read contains bytes that have been read from the endpoint,
	// but haven't yet been returned.
	read buffer.View
}

// NewConn creates a new Conn.
func NewConn(wq *waiter.Queue, ep tcpip.Endpoint) *Conn {
	c := &Conn{
		wq: wq,
		ep: ep,
	}
	c.deadlineTimer.init()
	return c
}

// Accept implements net.Conn.Accept.
func (l *Listener) Accept() (net.Conn, error) {
	n, wq, err := l.ep.Accept()

	if err == tcpip.ErrWouldBlock {
		// Create wait queue entry that notifies a channel.
		waitEntry, notifyCh := waiter.NewChannelEntry(nil)
		l.wq.EventRegister(&waitEntry, waiter.EventIn)
		defer l.wq.EventUnregister(&waitEntry)

		for {
			n, wq, err = l.ep.Accept()

			if err != tcpip.ErrWouldBlock {
				break
			}

			select {
			case <-l.cancel:
				return nil, errCanceled
			case <-notifyCh:
			}
		}
	}

	if err != nil {
		return nil, &net.OpError{
			Op:   "accept",
			Net:  "tcp",
			Addr: l.Addr(),
			Err:  errors.New(err.String()),
		}
	}

	return NewConn(wq, n), nil
}

type opErrorer interface {
	newOpError(op string, err error) *net.OpError
}

// commonRead implements the common logic between net.Conn.Read and
// net.PacketConn.ReadFrom.
func commonRead(ep tcpip.Endpoint, wq *waiter.Queue, deadline <-chan struct{}, addr *tcpip.FullAddress, errorer opErrorer, dontWait bool) ([]byte, error) {
	select {
	case <-deadline:
		return nil, errorer.newOpError("read", &timeoutError{})
	default:
	}

	read, _, err := ep.Read(addr)

	if err == tcpip.ErrWouldBlock {
		if dontWait {
			return nil, errWouldBlock
		}
		// Create wait queue entry that notifies a channel.
		waitEntry, notifyCh := waiter.NewChannelEntry(nil)
		wq.EventRegister(&waitEntry, waiter.EventIn)
		defer wq.EventUnregister(&waitEntry)
		for {
			read, _, err = ep.Read(addr)
			if err != tcpip.ErrWouldBlock {
				break
			}
			select {
			case <-deadline:
				return nil, errorer.newOpError("read", &timeoutError{})
			case <-notifyCh:
			}
		}
	}

	if err == tcpip.ErrClosedForReceive {
		return nil, io.EOF
	}

	if err != nil {
		return nil, errorer.newOpError("read", errors.New(err.String()))
	}

	return read, nil
}

// Read implements net.Conn.Read.
func (c *Conn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	deadline := c.readCancel()

	numRead := 0
	for numRead != len(b) {
		if len(c.read) == 0 {
			var err error
			c.read, err = commonRead(c.ep, c.wq, deadline, nil, c, numRead != 0)
			if err != nil {
				if numRead != 0 {
					return numRead, nil
				}
				return numRead, err
			}
		}
		n := copy(b[numRead:], c.read)
		c.read.TrimFront(n)
		numRead += n
		if len(c.read) == 0 {
			c.read = nil
		}
	}
	return numRead, nil
}

// Write implements net.Conn.Write.
func (c *Conn) Write(b []byte) (int, error) {
	deadline := c.writeCancel()

	// Check if deadlineTimer has already expired.
	select {
	case <-deadline:
		return 0, c.newOpError("write", &timeoutError{})
	default:
	}

	v := buffer.NewViewFromBytes(b)

	// We must handle two soft failure conditions simultaneously:
	//  1. Write may write nothing and return tcpip.ErrWouldBlock.
	//     If this happens, we need to register for notifications if we have
	//     not already and wait to try again.
	//  2. Write may write fewer than the full number of bytes and return
	//     without error. In this case we need to try writing the remaining
	//     bytes again. I do not need to register for notifications.
	//
	// What is more, these two soft failure conditions can be interspersed.
	// There is no guarantee that all of the condition #1s will occur before
	// all of the condition #2s or visa-versa.
	var (
		err      *tcpip.Error
		nbytes   int
		reg      bool
		notifyCh chan struct{}
	)
	for nbytes < len(b) && (err == tcpip.ErrWouldBlock || err == nil) {
		if err == tcpip.ErrWouldBlock {
			if !reg {
				// Only register once.
				reg = true

				// Create wait queue entry that notifies a channel.
				var waitEntry waiter.Entry
				waitEntry, notifyCh = waiter.NewChannelEntry(nil)
				c.wq.EventRegister(&waitEntry, waiter.EventOut)
				defer c.wq.EventUnregister(&waitEntry)
			} else {
				// Don't wait immediately after registration in case more data
				// became available between when we last checked and when we setup
				// the notification.
				select {
				case <-deadline:
					return nbytes, c.newOpError("write", &timeoutError{})
				case <-notifyCh:
				}
			}
		}

		var n uintptr
		var resCh <-chan struct{}
		n, resCh, err = c.ep.Write(tcpip.SlicePayload(v), tcpip.WriteOptions{})
		nbytes += int(n)
		v.TrimFront(int(n))

		if resCh != nil {
			select {
			case <-deadline:
				return nbytes, c.newOpError("write", &timeoutError{})
			case <-resCh:
			}

			n, _, err = c.ep.Write(tcpip.SlicePayload(v), tcpip.WriteOptions{})
			nbytes += int(n)
			v.TrimFront(int(n))
		}
	}

	if err == nil {
		return nbytes, nil
	}

	return nbytes, c.newOpError("write", errors.New(err.String()))
}

// Close implements net.Conn.Close.
func (c *Conn) Close() error {
	c.ep.Close()
	return nil
}

// CloseRead shuts down the reading side of the TCP connection. Most callers
// should just use Close.
//
// A TCP Half-Close is performed the same as CloseRead for *net.TCPConn.
func (c *Conn) CloseRead() error {
	if terr := c.ep.Shutdown(tcpip.ShutdownRead); terr != nil {
		return c.newOpError("close", errors.New(terr.String()))
	}
	return nil
}

// CloseWrite shuts down the writing side of the TCP connection. Most callers
// should just use Close.
//
// A TCP Half-Close is performed the same as CloseWrite for *net.TCPConn.
func (c *Conn) CloseWrite() error {
	if terr := c.ep.Shutdown(tcpip.ShutdownWrite); terr != nil {
		return c.newOpError("close", errors.New(terr.String()))
	}
	return nil
}

// LocalAddr implements net.Conn.LocalAddr.
func (c *Conn) LocalAddr() net.Addr {
	a, err := c.ep.GetLocalAddress()
	if err != nil {
		return nil
	}
	return fullToTCPAddr(a)
}

// RemoteAddr implements net.Conn.RemoteAddr.
func (c *Conn) RemoteAddr() net.Addr {
	a, err := c.ep.GetRemoteAddress()
	if err != nil {
		return nil
	}
	return fullToTCPAddr(a)
}

func (c *Conn) newOpError(op string, err error) *net.OpError {
	return &net.OpError{
		Op:     op,
		Net:    "tcp",
		Source: c.LocalAddr(),
		Addr:   c.RemoteAddr(),
		Err:    err,
	}
}

func fullToTCPAddr(addr tcpip.FullAddress) *net.TCPAddr {
	return &net.TCPAddr{IP: net.IP(addr.Addr), Port: int(addr.Port)}
}

func fullToUDPAddr(addr tcpip.FullAddress) *net.UDPAddr {
	return &net.UDPAddr{IP: net.IP(addr.Addr), Port: int(addr.Port)}
}

// DialTCP creates a new TCP Conn connected to the specified address.
func DialTCP(s *stack.Stack, addr tcpip.FullAddress, network tcpip.NetworkProtocolNumber) (*Conn, error) {
	return DialContextTCP(context.Background(), s, addr, network)
}

// DialContextTCP creates a new TCP Conn connected to the specified address
// with the option of adding cancellation and timeouts.
func DialContextTCP(ctx context.Context, s *stack.Stack, addr tcpip.FullAddress, network tcpip.NetworkProtocolNumber) (*Conn, error) {
	// Create TCP endpoint, then connect.
	var wq waiter.Queue
	ep, err := s.NewEndpoint(tcp.ProtocolNumber, network, &wq)
	if err != nil {
		return nil, errors.New(err.String())
	}

	// Create wait queue entry that notifies a channel.
	//
	// We do this unconditionally as Connect will always return an error.
	waitEntry, notifyCh := waiter.NewChannelEntry(nil)
	wq.EventRegister(&waitEntry, waiter.EventOut)
	defer wq.EventUnregister(&waitEntry)

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	err = ep.Connect(addr)
	if err == tcpip.ErrConnectStarted {
		select {
		case <-ctx.Done():
			ep.Close()
			return nil, ctx.Err()
		case <-notifyCh:
		}

		err = ep.GetSockOpt(tcpip.ErrorOption{})
	}
	if err != nil {
		ep.Close()
		return nil, &net.OpError{
			Op:   "connect",
			Net:  "tcp",
			Addr: fullToTCPAddr(addr),
			Err:  errors.New(err.String()),
		}
	}

	return NewConn(&wq, ep), nil
}

// A PacketConn is a wrapper around a tcpip endpoint that implements
// net.PacketConn.
type PacketConn struct {
	deadlineTimer

	stack *stack.Stack
	ep    tcpip.Endpoint
	wq    *waiter.Queue
}

// DialUDP creates a new PacketConn.
//
// If laddr is nil, a local address is automatically chosen.
//
// If raddr is nil, the PacketConn is left unconnected.
func DialUDP(s *stack.Stack, laddr, raddr *tcpip.FullAddress, network tcpip.NetworkProtocolNumber) (*PacketConn, error) {
	var wq waiter.Queue
	ep, err := s.NewEndpoint(udp.ProtocolNumber, network, &wq)
	if err != nil {
		return nil, errors.New(err.String())
	}

	if laddr != nil {
		if err := ep.Bind(*laddr); err != nil {
			ep.Close()
			return nil, &net.OpError{
				Op:   "bind",
				Net:  "udp",
				Addr: fullToUDPAddr(*laddr),
				Err:  errors.New(err.String()),
			}
		}
	}

	c := PacketConn{
		stack: s,
		ep:    ep,
		wq:    &wq,
	}
	c.deadlineTimer.init()

	if raddr != nil {
		if err := c.ep.Connect(*raddr); err != nil {
			c.ep.Close()
			return nil, &net.OpError{
				Op:   "connect",
				Net:  "udp",
				Addr: fullToUDPAddr(*raddr),
				Err:  errors.New(err.String()),
			}
		}
	}

	return &c, nil
}

func (c *PacketConn) newOpError(op string, err error) *net.OpError {
	return c.newRemoteOpError(op, nil, err)
}

func (c *PacketConn) newRemoteOpError(op string, remote net.Addr, err error) *net.OpError {
	return &net.OpError{
		Op:     op,
		Net:    "udp",
		Source: c.LocalAddr(),
		Addr:   remote,
		Err:    err,
	}
}

// RemoteAddr implements net.Conn.RemoteAddr.
func (c *PacketConn) RemoteAddr() net.Addr {
	a, err := c.ep.GetRemoteAddress()
	if err != nil {
		return nil
	}
	return fullToTCPAddr(a)
}

// Read implements net.Conn.Read
func (c *PacketConn) Read(b []byte) (int, error) {
	bytesRead, _, err := c.ReadFrom(b)
	return bytesRead, err
}

// ReadFrom implements net.PacketConn.ReadFrom.
func (c *PacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	deadline := c.readCancel()

	var addr tcpip.FullAddress
	read, err := commonRead(c.ep, c.wq, deadline, &addr, c, false)
	if err != nil {
		return 0, nil, err
	}

	return copy(b, read), fullToUDPAddr(addr), nil
}

func (c *PacketConn) Write(b []byte) (int, error) {
	return c.WriteTo(b, nil)
}

// WriteTo implements net.PacketConn.WriteTo.
func (c *PacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	deadline := c.writeCancel()

	// Check if deadline has already expired.
	select {
	case <-deadline:
		return 0, c.newRemoteOpError("write", addr, &timeoutError{})
	default:
	}

	// If we're being called by Write, there is no addr
	wopts := tcpip.WriteOptions{}
	if addr != nil {
		ua := addr.(*net.UDPAddr)
		wopts.To = &tcpip.FullAddress{Addr: tcpip.Address(ua.IP), Port: uint16(ua.Port)}
	}

	v := buffer.NewView(len(b))
	copy(v, b)

	n, resCh, err := c.ep.Write(tcpip.SlicePayload(v), wopts)
	if resCh != nil {
		select {
		case <-deadline:
			return int(n), c.newRemoteOpError("write", addr, &timeoutError{})
		case <-resCh:
		}

		n, _, err = c.ep.Write(tcpip.SlicePayload(v), wopts)
	}

	if err == tcpip.ErrWouldBlock {
		// Create wait queue entry that notifies a channel.
		waitEntry, notifyCh := waiter.NewChannelEntry(nil)
		c.wq.EventRegister(&waitEntry, waiter.EventOut)
		defer c.wq.EventUnregister(&waitEntry)
		for {
			select {
			case <-deadline:
				return int(n), c.newRemoteOpError("write", addr, &timeoutError{})
			case <-notifyCh:
			}

			n, _, err = c.ep.Write(tcpip.SlicePayload(v), wopts)
			if err != tcpip.ErrWouldBlock {
				break
			}
		}
	}

	if err == nil {
		return int(n), nil
	}

	return int(n), c.newRemoteOpError("write", addr, errors.New(err.String()))
}

// Close implements net.PacketConn.Close.
func (c *PacketConn) Close() error {
	c.ep.Close()
	return nil
}

// LocalAddr implements net.PacketConn.LocalAddr.
func (c *PacketConn) LocalAddr() net.Addr {
	a, err := c.ep.GetLocalAddress()
	if err != nil {
		return nil
	}
	return fullToUDPAddr(a)
}
