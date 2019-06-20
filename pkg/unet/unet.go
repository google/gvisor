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

// Package unet provides a minimal net package based on Unix Domain Sockets.
//
// This does no pooling, and should only be used for a limited number of
// connections in a Go process. Don't use this package for arbitrary servers.
package unet

import (
	"errors"
	"sync/atomic"
	"syscall"

	"gvisor.dev/gvisor/pkg/gate"
)

// backlog is used for the listen request.
const backlog = 16

// errClosing is returned by wait if the Socket is in the process of closing.
var errClosing = errors.New("Socket is closing")

// errMessageTruncated indicates that data was lost because the provided buffer
// was too small.
var errMessageTruncated = errors.New("message truncated")

// socketType returns the appropriate type.
func socketType(packet bool) int {
	if packet {
		return syscall.SOCK_SEQPACKET
	}
	return syscall.SOCK_STREAM
}

// socket creates a new host socket.
func socket(packet bool) (int, error) {
	// Make a new socket.
	fd, err := syscall.Socket(syscall.AF_UNIX, socketType(packet), 0)
	if err != nil {
		return 0, err
	}

	return fd, nil
}

// eventFD returns a new event FD with initial value 0.
func eventFD() (int, error) {
	f, _, e := syscall.Syscall(syscall.SYS_EVENTFD2, 0, 0, 0)
	if e != 0 {
		return -1, e
	}
	return int(f), nil
}

// Socket is a connected unix domain socket.
type Socket struct {
	// gate protects use of fd.
	gate gate.Gate

	// fd is the bound socket.
	//
	// fd must be read atomically, and only remains valid if read while
	// within gate.
	fd int32

	// efd is an event FD that is signaled when the socket is closing.
	//
	// efd is immutable and remains valid until Close/Release.
	efd int

	// race is an atomic variable used to avoid triggering the race
	// detector. See comment in SocketPair below.
	race *int32
}

// NewSocket returns a socket from an existing FD.
//
// NewSocket takes ownership of fd.
func NewSocket(fd int) (*Socket, error) {
	// fd must be non-blocking for non-blocking syscall.Accept in
	// ServerSocket.Accept.
	if err := syscall.SetNonblock(fd, true); err != nil {
		return nil, err
	}

	efd, err := eventFD()
	if err != nil {
		return nil, err
	}

	return &Socket{
		fd:  int32(fd),
		efd: efd,
	}, nil
}

// finish completes use of s.fd by evicting any waiters, closing the gate, and
// closing the event FD.
func (s *Socket) finish() error {
	// Signal any blocked or future polls.
	//
	// N.B. eventfd writes must be 8 bytes.
	if _, err := syscall.Write(s.efd, []byte{1, 0, 0, 0, 0, 0, 0, 0}); err != nil {
		return err
	}

	// Close the gate, blocking until all FD users leave.
	s.gate.Close()

	return syscall.Close(s.efd)
}

// Close closes the socket.
func (s *Socket) Close() error {
	// Set the FD in the socket to -1, to ensure that all future calls to
	// FD/Release get nothing and Close calls return immediately.
	fd := int(atomic.SwapInt32(&s.fd, -1))
	if fd < 0 {
		// Already closed or closing.
		return syscall.EBADF
	}

	// Shutdown the socket to cancel any pending accepts.
	s.shutdown(fd)

	if err := s.finish(); err != nil {
		return err
	}

	return syscall.Close(fd)
}

// Release releases ownership of the socket FD.
//
// The returned FD is non-blocking.
//
// Any concurrent or future callers of Socket methods will receive EBADF.
func (s *Socket) Release() (int, error) {
	// Set the FD in the socket to -1, to ensure that all future calls to
	// FD/Release get nothing and Close calls return immediately.
	fd := int(atomic.SwapInt32(&s.fd, -1))
	if fd < 0 {
		// Already closed or closing.
		return -1, syscall.EBADF
	}

	if err := s.finish(); err != nil {
		return -1, err
	}

	return fd, nil
}

// FD returns the FD for this Socket.
//
// The FD is non-blocking and must not be made blocking.
//
// N.B. os.File.Fd makes the FD blocking. Use of Release instead of FD is
// strongly preferred.
//
// The returned FD cannot be used safely if there may be concurrent callers to
// Close or Release.
//
// Use Release to take ownership of the FD.
func (s *Socket) FD() int {
	return int(atomic.LoadInt32(&s.fd))
}

// enterFD enters the FD gate and returns the FD value.
//
// If enterFD returns ok, s.gate.Leave must be called when done with the FD.
// Callers may only block while within the gate using s.wait.
//
// The returned FD is guaranteed to remain valid until s.gate.Leave.
func (s *Socket) enterFD() (int, bool) {
	if !s.gate.Enter() {
		return -1, false
	}

	fd := int(atomic.LoadInt32(&s.fd))
	if fd < 0 {
		s.gate.Leave()
		return -1, false
	}

	return fd, true
}

// SocketPair creates a pair of connected sockets.
func SocketPair(packet bool) (*Socket, *Socket, error) {
	// Make a new pair.
	fds, err := syscall.Socketpair(syscall.AF_UNIX, socketType(packet)|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}

	// race is an atomic variable used to avoid triggering the race
	// detector. We have to fool TSAN into thinking there is a race
	// variable between our two sockets. We only use SocketPair in tests
	// anyway.
	//
	// NOTE(b/27107811): This is purely due to the fact that the raw
	// syscall does not serve as a boundary for the sanitizer.
	var race int32
	a, err := NewSocket(fds[0])
	if err != nil {
		syscall.Close(fds[0])
		syscall.Close(fds[1])
		return nil, nil, err
	}
	a.race = &race
	b, err := NewSocket(fds[1])
	if err != nil {
		a.Close()
		syscall.Close(fds[1])
		return nil, nil, err
	}
	b.race = &race
	return a, b, nil
}

// Connect connects to a server.
func Connect(addr string, packet bool) (*Socket, error) {
	fd, err := socket(packet)
	if err != nil {
		return nil, err
	}

	// Connect the socket.
	usa := &syscall.SockaddrUnix{Name: addr}
	if err := syscall.Connect(fd, usa); err != nil {
		syscall.Close(fd)
		return nil, err
	}

	return NewSocket(fd)
}

// ControlMessage wraps around a byte array and provides functions for parsing
// as a Unix Domain Socket control message.
type ControlMessage []byte

// EnableFDs enables receiving FDs via control message.
//
// This guarantees only a MINIMUM number of FDs received. You may receive MORE
// than this due to the way FDs are packed. To be specific, the number of
// receivable buffers will be rounded up to the nearest even number.
//
// This must be called prior to ReadVec if you want to receive FDs.
func (c *ControlMessage) EnableFDs(count int) {
	*c = make([]byte, syscall.CmsgSpace(count*4))
}

// ExtractFDs returns the list of FDs in the control message.
//
// Either this or CloseFDs should be used after EnableFDs.
func (c *ControlMessage) ExtractFDs() ([]int, error) {
	msgs, err := syscall.ParseSocketControlMessage(*c)
	if err != nil {
		return nil, err
	}
	var fds []int
	for _, msg := range msgs {
		thisFds, err := syscall.ParseUnixRights(&msg)
		if err != nil {
			// Different control message.
			return nil, err
		}
		for _, fd := range thisFds {
			if fd >= 0 {
				fds = append(fds, fd)
			}
		}
	}
	return fds, nil
}

// CloseFDs closes the list of FDs in the control message.
//
// Either this or ExtractFDs should be used after EnableFDs.
func (c *ControlMessage) CloseFDs() {
	fds, _ := c.ExtractFDs()
	for _, fd := range fds {
		if fd >= 0 {
			syscall.Close(fd)
		}
	}
}

// PackFDs packs the given list of FDs in the control message.
//
// This must be used prior to WriteVec.
func (c *ControlMessage) PackFDs(fds ...int) {
	*c = ControlMessage(syscall.UnixRights(fds...))
}

// UnpackFDs clears the control message.
func (c *ControlMessage) UnpackFDs() {
	*c = nil
}

// SocketWriter wraps an individual send operation.
//
// The normal entrypoint is WriteVec.
type SocketWriter struct {
	socket   *Socket
	to       []byte
	blocking bool
	race     *int32

	ControlMessage
}

// Writer returns a writer for this socket.
func (s *Socket) Writer(blocking bool) SocketWriter {
	return SocketWriter{socket: s, blocking: blocking, race: s.race}
}

// Write implements io.Writer.Write.
func (s *Socket) Write(p []byte) (int, error) {
	r := s.Writer(true)
	return r.WriteVec([][]byte{p})
}

// GetSockOpt gets the given socket option.
func (s *Socket) GetSockOpt(level int, name int, b []byte) (uint32, error) {
	fd, ok := s.enterFD()
	if !ok {
		return 0, syscall.EBADF
	}
	defer s.gate.Leave()

	return getsockopt(fd, level, name, b)
}

// SetSockOpt sets the given socket option.
func (s *Socket) SetSockOpt(level, name int, b []byte) error {
	fd, ok := s.enterFD()
	if !ok {
		return syscall.EBADF
	}
	defer s.gate.Leave()

	return setsockopt(fd, level, name, b)
}

// GetSockName returns the socket name.
func (s *Socket) GetSockName() ([]byte, error) {
	fd, ok := s.enterFD()
	if !ok {
		return nil, syscall.EBADF
	}
	defer s.gate.Leave()

	var buf []byte
	l := syscall.SizeofSockaddrAny

	for {
		// If the buffer is not large enough, allocate a new one with the hint.
		buf = make([]byte, l)
		l, err := getsockname(fd, buf)
		if err != nil {
			return nil, err
		}

		if l <= uint32(len(buf)) {
			return buf[:l], nil
		}
	}
}

// GetPeerName returns the peer name.
func (s *Socket) GetPeerName() ([]byte, error) {
	fd, ok := s.enterFD()
	if !ok {
		return nil, syscall.EBADF
	}
	defer s.gate.Leave()

	var buf []byte
	l := syscall.SizeofSockaddrAny

	for {
		// See above.
		buf = make([]byte, l)
		l, err := getpeername(fd, buf)
		if err != nil {
			return nil, err
		}

		if l <= uint32(len(buf)) {
			return buf[:l], nil
		}
	}
}

// GetPeerCred returns the peer's unix credentials.
func (s *Socket) GetPeerCred() (*syscall.Ucred, error) {
	fd, ok := s.enterFD()
	if !ok {
		return nil, syscall.EBADF
	}
	defer s.gate.Leave()

	return syscall.GetsockoptUcred(fd, syscall.SOL_SOCKET, syscall.SO_PEERCRED)
}

// SocketReader wraps an individual receive operation.
//
// This may be used for doing vectorized reads and/or sending additional
// control messages (e.g. FDs). The normal entrypoint is ReadVec.
//
// One of ExtractFDs or DisposeFDs must be called if EnableFDs is used.
type SocketReader struct {
	socket   *Socket
	source   []byte
	blocking bool
	race     *int32

	ControlMessage
}

// Reader returns a reader for this socket.
func (s *Socket) Reader(blocking bool) SocketReader {
	return SocketReader{socket: s, blocking: blocking, race: s.race}
}

// Read implements io.Reader.Read.
func (s *Socket) Read(p []byte) (int, error) {
	r := s.Reader(true)
	return r.ReadVec([][]byte{p})
}

func (s *Socket) shutdown(fd int) error {
	// Shutdown the socket to cancel any pending accepts.
	return syscall.Shutdown(fd, syscall.SHUT_RDWR)
}

// Shutdown closes the socket for read and write.
func (s *Socket) Shutdown() error {
	fd, ok := s.enterFD()
	if !ok {
		return syscall.EBADF
	}
	defer s.gate.Leave()

	return s.shutdown(fd)
}

// ServerSocket is a bound unix domain socket.
type ServerSocket struct {
	socket *Socket
}

// NewServerSocket returns a socket from an existing FD.
func NewServerSocket(fd int) (*ServerSocket, error) {
	s, err := NewSocket(fd)
	if err != nil {
		return nil, err
	}
	return &ServerSocket{socket: s}, nil
}

// Bind creates and binds a new socket.
func Bind(addr string, packet bool) (*ServerSocket, error) {
	fd, err := socket(packet)
	if err != nil {
		return nil, err
	}

	// Do the bind.
	usa := &syscall.SockaddrUnix{Name: addr}
	if err := syscall.Bind(fd, usa); err != nil {
		syscall.Close(fd)
		return nil, err
	}

	return NewServerSocket(fd)
}

// BindAndListen creates, binds and listens on a new socket.
func BindAndListen(addr string, packet bool) (*ServerSocket, error) {
	s, err := Bind(addr, packet)
	if err != nil {
		return nil, err
	}

	// Start listening.
	if err := s.Listen(); err != nil {
		s.Close()
		return nil, err
	}

	return s, nil
}

// Listen starts listening on the socket.
func (s *ServerSocket) Listen() error {
	fd, ok := s.socket.enterFD()
	if !ok {
		return syscall.EBADF
	}
	defer s.socket.gate.Leave()

	return syscall.Listen(fd, backlog)
}

// Accept accepts a new connection.
//
// This is always blocking.
//
// Preconditions:
//  * ServerSocket is listening (Listen called).
func (s *ServerSocket) Accept() (*Socket, error) {
	fd, ok := s.socket.enterFD()
	if !ok {
		return nil, syscall.EBADF
	}
	defer s.socket.gate.Leave()

	for {
		nfd, _, err := syscall.Accept(fd)
		switch err {
		case nil:
			return NewSocket(nfd)
		case syscall.EAGAIN:
			err = s.socket.wait(false)
			if err == errClosing {
				err = syscall.EBADF
			}
		}
		if err != nil {
			return nil, err
		}
	}
}

// Close closes the server socket.
//
// This must only be called once.
func (s *ServerSocket) Close() error {
	return s.socket.Close()
}

// FD returns the socket's file descriptor.
//
// See Socket.FD.
func (s *ServerSocket) FD() int {
	return s.socket.FD()
}

// Release releases ownership of the socket's file descriptor.
//
// See Socket.Release.
func (s *ServerSocket) Release() (int, error) {
	return s.socket.Release()
}
