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
	"io"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// mockEndpoint defines an endpoint that tests can read and write for validating portforwarders.
type mockEndpoint interface {
	read(n int) ([]byte, error)
	write(buf []byte) (int, error)
}

// portforwarderTestHarness mocks both sides of the portforwarder connection so that behavior can be
// validated between them.
type portforwarderTestHarness struct {
	app  mockEndpoint
	shim mockEndpoint
}

func (th *portforwarderTestHarness) appWrite(buf []byte) (int, error) {
	return th.app.write(buf)
}

func (th *portforwarderTestHarness) appRead(n int) ([]byte, error) {
	return th.doRead(n, th.app)
}

func (th *portforwarderTestHarness) shimWrite(buf []byte) (int, error) {
	return th.shim.write(buf)
}

func (th *portforwarderTestHarness) shimRead(n int) ([]byte, error) {
	return th.doRead(n, th.shim)
}

func (th *portforwarderTestHarness) doRead(n int, ep mockEndpoint) ([]byte, error) {
	buf := make([]byte, 0, n)
	for {
		out, err := ep.read(n - len(buf))
		if err != nil && !linuxerr.Equals(linuxerr.ErrWouldBlock, err) {
			return nil, err
		}
		buf = append(buf, out...)
		if len(buf) >= n {
			return buf, nil
		}
	}
}

// mockApplicationFDImpl mocks a VFS file description endpoint on which the sandboxed application
// and the portforwarder will communicate.
type mockApplicationFDImpl struct {
	vfs.FileDescriptionDefaultImpl
	vfs.NoLockFD
	vfs.DentryMetadataFileDescriptionImpl
	mu         sync.Mutex
	readBuf    bytes.Buffer
	writeBuf   bytes.Buffer
	released   bool
	queue      waiter.Queue
	notifyStop chan struct{}
}

var _ vfs.FileDescriptionImpl = (*mockApplicationFDImpl)(nil)

func newMockApplicationFDImpl() *mockApplicationFDImpl {
	app := &mockApplicationFDImpl{notifyStop: make(chan struct{})}
	go app.doNotify()
	return app
}

// Read implements vfs.FileDescriptionImpl.Read details for the parent mockFileDescription.
func (s *mockApplicationFDImpl) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.released {
		return 0, io.EOF
	}
	if s.readBuf.Len() == 0 {
		return 0, linuxerr.ErrWouldBlock
	}
	buf := s.readBuf.Next(s.readBuf.Len())
	n, err := dst.CopyOut(ctx, buf)
	return int64(n), err
}

// Write implements vfs.FileDescriptionImpl.Write details for the parent mockFileDescription.
func (s *mockApplicationFDImpl) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.released {
		return 0, io.EOF
	}

	buf := make([]byte, src.NumBytes())
	n, _ := src.CopyIn(ctx, buf)
	res, _ := s.writeBuf.Write(buf[:n])
	return int64(res), nil
}

// write implements mockEndpoint.write.
func (s *mockApplicationFDImpl) write(buf []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.released {
		return 0, io.EOF
	}
	ret, err := s.readBuf.Write(buf)
	return ret, err
}

// read implements mockEndpoint.read.
func (s *mockApplicationFDImpl) read(n int) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.released {
		return nil, io.EOF
	}
	if s.writeBuf.Len() == 0 {
		return nil, linuxerr.ErrWouldBlock
	}
	ret := s.writeBuf.Next(n)
	return ret, nil
}

func (s *mockApplicationFDImpl) doNotify() {
	for {
		s.queue.Notify(waiter.ReadableEvents | waiter.WritableEvents | waiter.EventHUp)
		select {
		case <-s.notifyStop:
			return
		default:
			time.Sleep(time.Millisecond * 50)
		}
	}
}

func (s *mockApplicationFDImpl) IsReadable() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.released {
		return false
	}
	return s.readBuf.Len() > 0
}

func (s *mockApplicationFDImpl) IsWritable() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.released
}

// EventRegister implements vfs.FileDescriptionImpl.EventRegister details for the parent mockFileDescription.
func (s *mockApplicationFDImpl) EventRegister(we *waiter.Entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queue.EventRegister(we)
	return nil
}

// EventUnregister implements vfs.FileDescriptionImpl.Unregister details for the parent mockFileDescription.
func (s *mockApplicationFDImpl) EventUnregister(we *waiter.Entry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queue.EventUnregister(we)
}

// Release implements vfs.FileDescriptionImpl.Release details for the parent mockFileDescription.
func (s *mockApplicationFDImpl) Release(context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.released = true
	s.notifyStop <- struct{}{}
}

// mockTCPEndpointImpl is the subset of methods used by tests for the mockTCPEndpoint struct. This
// is so we can quickly change implementations as needed.
type mockTCPEndpointImpl interface {
	Close()
	Read(io.Writer, tcpip.ReadOptions) (tcpip.ReadResult, tcpip.Error)
	Write(tcpip.Payloader, tcpip.WriteOptions) (int64, tcpip.Error)
	Shutdown(tcpip.ShutdownFlags) tcpip.Error
}

// mockTCPEndpoint mocks tcpip.Endpoint for tests.
type mockTCPEndpoint struct {
	impl       mockTCPEndpointImpl // impl implements the subset of methods needed for mockTCPEndpoints.
	wq         *waiter.Queue
	notifyDone chan struct{}
}

func newMockTCPEndpoint(impl mockTCPEndpointImpl, wq *waiter.Queue) *mockTCPEndpoint {
	ret := &mockTCPEndpoint{
		impl:       impl,
		wq:         wq,
		notifyDone: make(chan struct{}),
	}

	go ret.doNotify()
	return ret
}

func (m *mockTCPEndpoint) doNotify() {
	for {
		m.wq.Notify(waiter.ReadableEvents | waiter.WritableEvents | waiter.EventHUp)
		select {
		case <-m.notifyDone:
			return
		default:
			time.Sleep(time.Millisecond * 50)
		}

	}
}

// The below are trivial stub methods to get mockTCPEndpoint to implement tcpip.Endpoint. They
// either panic or call the contained impl's methods.

// Close implements tcpip.Endpoint.Close.
func (m *mockTCPEndpoint) Close() {
	m.impl.Close()
	m.notifyDone <- struct{}{}
}

// Abort implements tcpip.Endpoint.Abort.
func (m *mockTCPEndpoint) Abort() {
	m.panicWithNotImplementedMsg()
}

// Read implements tcpip.Endpoint.Read.
func (m *mockTCPEndpoint) Read(w io.Writer, opts tcpip.ReadOptions) (tcpip.ReadResult, tcpip.Error) {
	return m.impl.Read(w, opts)
}

// Write implements tcpip.Endpoint.Write.
func (m *mockTCPEndpoint) Write(payload tcpip.Payloader, opts tcpip.WriteOptions) (int64, tcpip.Error) {
	return m.impl.Write(payload, opts)
}

// Connect implements tcpip.Endpoint.Connect.
func (m *mockTCPEndpoint) Connect(address tcpip.FullAddress) tcpip.Error {
	m.panicWithNotImplementedMsg()
	return nil
}

// Disconnect implements tcpip.Endpoint.Disconnect.
func (m *mockTCPEndpoint) Disconnect() tcpip.Error {
	m.panicWithNotImplementedMsg()
	return nil
}

// Shutdown implements tcpip.Endpoint.Shutdown.
func (m *mockTCPEndpoint) Shutdown(flags tcpip.ShutdownFlags) tcpip.Error {
	return m.impl.Shutdown(flags)
}

// Listen implements tcpip.Endpoint.Listen.
func (m *mockTCPEndpoint) Listen(backlog int) tcpip.Error {
	m.panicWithNotImplementedMsg()
	return nil
}

// Accept implements tcpip.Endpoint.Accept.
func (m *mockTCPEndpoint) Accept(peerAddr *tcpip.FullAddress) (tcpip.Endpoint, *waiter.Queue, tcpip.Error) {
	m.panicWithNotImplementedMsg()
	return nil, nil, nil
}

// Bind implements tcpip.Endpoint.Bind.
func (m *mockTCPEndpoint) Bind(address tcpip.FullAddress) tcpip.Error {
	m.panicWithNotImplementedMsg()
	return nil
}

// GetLocalAddress implements tcpip.Endpoint.GetLocalAddress.
func (m mockTCPEndpoint) GetLocalAddress() (tcpip.FullAddress, tcpip.Error) {
	m.panicWithNotImplementedMsg()
	return tcpip.FullAddress{}, nil
}

// GetRemoteAddress implements tcpip.Endpoint.GetRemoreAddress.
func (m *mockTCPEndpoint) GetRemoteAddress() (tcpip.FullAddress, tcpip.Error) {
	m.panicWithNotImplementedMsg()
	return tcpip.FullAddress{}, nil
}

// Readiness implements tcpip.Endpoint.Readiness.
func (m *mockTCPEndpoint) Readiness(mask waiter.EventMask) waiter.EventMask {
	m.panicWithNotImplementedMsg()
	return 0
}

// SetSockOpt implements tcpip.Endpoint.SetSockOpt.
func (m *mockTCPEndpoint) SetSockOpt(opt tcpip.SettableSocketOption) tcpip.Error {
	m.panicWithNotImplementedMsg()
	return nil
}

// SetSockOptInt implements tcpip.Endpoint.SetSockOptInt.
func (m *mockTCPEndpoint) SetSockOptInt(opt tcpip.SockOptInt, v int) tcpip.Error {
	m.panicWithNotImplementedMsg()
	return nil
}

// GetSockOpt implements tcpip.Endpoint.GetSockOpt.
func (m *mockTCPEndpoint) GetSockOpt(opt tcpip.GettableSocketOption) tcpip.Error {
	m.panicWithNotImplementedMsg()
	return nil
}

// GetSockOptInt implements tcpip.Endpoint.GetSockOpt.
func (m *mockTCPEndpoint) GetSockOptInt(tcpip.SockOptInt) (int, tcpip.Error) {
	m.panicWithNotImplementedMsg()
	return 0, nil
}

// State implements tcpip.Endpoint.State.
func (m *mockTCPEndpoint) State() uint32 {
	m.panicWithNotImplementedMsg()
	return 0
}

// ModerateRecvBuf implements tcpip.Endpoint.ModerateRecvBuf
func (m *mockTCPEndpoint) ModerateRecvBuf(copied int) {
	m.panicWithNotImplementedMsg()
}

// Info implements tcpip.Endpoint.Info.
func (m *mockTCPEndpoint) Info() tcpip.EndpointInfo {
	m.panicWithNotImplementedMsg()
	return nil
}

// Stats implements tcpip.Endpoint.Stats.
func (m *mockTCPEndpoint) Stats() tcpip.EndpointStats {
	m.panicWithNotImplementedMsg()
	return nil
}

// SetOwner implements tcpip.Endpoint.SetOwner.
func (m *mockTCPEndpoint) SetOwner(owner tcpip.PacketOwner) {
	m.panicWithNotImplementedMsg()
}

// LastError implements tcpip.Endpoint.LastError.
func (m *mockTCPEndpoint) LastError() tcpip.Error {
	m.panicWithNotImplementedMsg()
	return nil
}

// SocketOptions implements tcpip.Endpoint.SocketOptions.
func (m *mockTCPEndpoint) SocketOptions() *tcpip.SocketOptions {
	m.panicWithNotImplementedMsg()
	return nil
}

func (*mockTCPEndpoint) panicWithNotImplementedMsg() { panic("not implemented") }
