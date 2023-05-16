// Copyright 2023 The gVisor Authors.
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

package portforward

import (
	"bytes"
	"fmt"
	"io"
	"sync"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// netstackConn allows reading and writing to a netstack endpoint.
// netstackConn implements proxyConn.
type netstackConn struct {
	// ep is the tcpip.Endpoint on which to read and write.
	ep tcpip.Endpoint
	// port is the port on which to connect.
	port uint16
	// wq is the WaitQueue for this connection to wait on notifications.
	wq *waiter.Queue
	// once makes sure Close is called once.
	once sync.Once
}

// NewNetstackConn creates a new port forwarding connection to the given
// port in netstack mode.
func NewNetstackConn(stack *stack.Stack, port uint16) (proxyConn, error) {
	var wq waiter.Queue
	ep, tcpErr := stack.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if tcpErr != nil {
		return nil, fmt.Errorf("creating endpoint: %v", tcpErr)
	}
	n := &netstackConn{
		ep:   ep,
		port: port,
		wq:   &wq,
	}
	waitEntry, notifyCh := waiter.NewChannelEntry(waiter.WritableEvents)
	n.wq.EventRegister(&waitEntry)
	defer n.wq.EventUnregister(&waitEntry)

	tcpErr = n.ep.Connect(tcpip.FullAddress{
		Addr: tcpip.AddrFrom4([4]byte{0x7f, 0x00, 0x00, 0x01}), // 127.0.0.1
		Port: n.port,
	})
	if _, ok := tcpErr.(*tcpip.ErrConnectStarted); ok {
		<-notifyCh
		tcpErr = n.ep.LastError()
	}
	if tcpErr != nil {
		return nil, fmt.Errorf("connecting endpoint: %v", tcpErr)
	}
	return n, nil
}

// Name implements proxyConn.Name.
func (n *netstackConn) Name() string {
	return fmt.Sprintf("netstack:port:%d", n.port)
}

// bufWriter is used as an io.Writer to read from tcpip.Endpoint.
type bufWriter struct {
	buf    []byte
	offset int64
}

// Write implements io.Writer.
func (b *bufWriter) Write(buf []byte) (int, error) {
	n := copy(b.buf[b.offset:], buf)
	b.offset += int64(n)
	return n, nil
}

// Read implements proxyConn.Read.
func (n *netstackConn) Read(ctx context.Context, buf []byte, cancel <-chan struct{}) (int, error) {
	var ch chan struct{}
	var e waiter.Entry
	b := &bufWriter{
		buf: buf,
	}
	res, tcpErr := n.ep.Read(b, tcpip.ReadOptions{})
	for _, ok := tcpErr.(*tcpip.ErrWouldBlock); ok && ctx.Err() == nil; _, ok = tcpErr.(*tcpip.ErrWouldBlock) {
		if ch == nil {
			e, ch = waiter.NewChannelEntry(waiter.ReadableEvents | waiter.EventIn | waiter.EventHUp | waiter.EventErr)
			n.wq.EventRegister(&e)
			defer n.wq.EventUnregister(&e)
		}
		select {
		case <-ch:
		case <-cancel:
			return 0, io.EOF
		case <-ctx.Done():
			return 0, ctx.Err()
		}
		res, tcpErr = n.ep.Read(b, tcpip.ReadOptions{})
	}
	if tcpErr != nil {
		return 0, io.EOF
	}
	return res.Total, nil
}

// Write implements proxyConn.Write.
func (n *netstackConn) Write(ctx context.Context, buf []byte, cancel <-chan struct{}) (int, error) {
	var ch chan struct{}
	var e waiter.Entry
	var b bytes.Reader
	b.Reset(buf)
	res, tcpErr := n.ep.Write(&b, tcpip.WriteOptions{Atomic: true})
	for _, ok := tcpErr.(*tcpip.ErrWouldBlock); ok && ctx.Err() == nil; _, ok = tcpErr.(*tcpip.ErrWouldBlock) {
		if ch == nil {
			e, ch = waiter.NewChannelEntry(waiter.WritableEvents | waiter.EventIn | waiter.EventHUp | waiter.EventErr)
			n.wq.EventRegister(&e)
			defer n.wq.EventUnregister(&e)
		}
		select {
		case <-ch:
		case <-cancel:
			return 0, io.EOF
		case <-ctx.Done():
			return 0, ctx.Err()
		}
		res, tcpErr = n.ep.Write(&b, tcpip.WriteOptions{Atomic: true})
	}
	if tcpErr != nil {
		return 0, io.EOF
	}
	return int(res), nil
}

// Close implements proxyConn.Close.
func (n *netstackConn) Close(_ context.Context) {
	n.once.Do(func() { n.ep.Close() })
}
