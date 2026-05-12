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

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	sys "syscall"
	"time"

	"github.com/google/subcommands"
	"gvisor.dev/gvisor/runsc/flag"
)

// hostinetSR opens TCP, UDP, listening, and epoll-registered sockets, then
// continuously logs the result of operations against them so tests can
// observe socket behavior across checkpoint/restore.
type hostinetSR struct {
	file   string
	target string
	tcpRaw sys.RawConn
	udpRaw sys.RawConn
}

// Name implements subcommands.Command.Name.
func (*hostinetSR) Name() string {
	return "hostinet-sr"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*hostinetSR) Synopsis() string {
	return "exercises hostinet checkpoint/restore sockets"
}

// Usage implements subcommands.Command.Usage.
func (*hostinetSR) Usage() string {
	return "hostinet-sr --file=<path> --target=<tcp addr>"
}

// SetFlags implements subcommands.Command.SetFlags.
func (h *hostinetSR) SetFlags(f *flag.FlagSet) {
	f.StringVar(&h.file, "file", "", "file for test output")
	f.StringVar(&h.target, "target", "", "TCP server address")
}

// Execute implements subcommands.Command.Execute.
func (h *hostinetSR) Execute(ctx context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	if h.file == "" || h.target == "" {
		log.Fatalf("--file and --target are required")
	}

	tcpConn, err := net.Dial("tcp", h.target)
	if err != nil {
		log.Fatalf("Dial(%q): %v", h.target, err)
	}
	defer tcpConn.Close()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("Listen: %v", err)
	}
	defer listener.Close()

	udpConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("ListenPacket: %v", err)
	}
	defer udpConn.Close()

	h.tcpRaw = h.mustRawConn(tcpConn.(*net.TCPConn))
	h.udpRaw = h.mustRawConn(udpConn.(*net.UDPConn))

	epollFD, err := sys.EpollCreate1(0)
	if err != nil {
		log.Fatalf("EpollCreate1: %v", err)
	}
	defer sys.Close(epollFD)

	var tcpFD int
	if err := h.tcpRaw.Control(func(fd uintptr) {
		tcpFD = int(fd)
	}); err != nil {
		log.Fatalf("Control: %v", err)
	}
	if err := sys.EpollCtl(epollFD, sys.EPOLL_CTL_ADD, tcpFD, &sys.EpollEvent{
		Events: sys.EPOLLIN,
		Fd:     int32(tcpFD),
	}); err != nil {
		log.Fatalf("EpollCtl: %v", err)
	}

	h.logf("LISTENER_ADDR=%s", listener.Addr())
	h.logf("SETUP_DONE")
	go h.blockingAccept(listener)
	for i := 0; ; i++ {
		h.logf("COUNT=%d", i)
		h.checkTCP(tcpConn)
		h.checkUDP(udpConn)
		h.checkEpoll(epollFD)
		time.Sleep(200 * time.Millisecond)
	}
}

// checkTCP logs the result of a write and read on the TCP connection, and
// dials a fresh connection once the existing one returns ECONNABORTED.
func (h *hostinetSR) checkTCP(conn net.Conn) {
	_, err := conn.Write([]byte("x"))
	h.logResult("TCP_WRITE", err)
	if errno, ok := errnoOf(err); ok && errno == sys.ECONNABORTED {
		newConn, err := net.Dial("tcp", h.target)
		h.logResult("NEW_TCP_DIAL", err)
		if err == nil {
			_, err = newConn.Write([]byte("x"))
			h.logResult("NEW_TCP_WRITE", err)
			newConn.Close()
		}
	}

	h.logResult("TCP_READ", rawRead(h.tcpRaw))
}

// checkUDP logs the result of a sendto and recvfrom on the UDP socket.
func (h *hostinetSR) checkUDP(conn net.PacketConn) {
	h.logResult("UDP_WRITE", rawSendto(h.udpRaw))
	h.logResult("UDP_READ", rawRecvfrom(h.udpRaw))
}

// blockingAccept blocks in accept and logs the result when it returns.
func (h *hostinetSR) blockingAccept(listener net.Listener) {
	conn, err := listener.Accept()
	h.logResult("BLOCKING_ACCEPT", err)
	if err == nil {
		conn.Close()
	}
}

// rawRead reads one byte directly from the connection's fd.
func rawRead(raw sys.RawConn) error {
	var buf [1]byte
	var opErr error
	err := raw.Read(func(fd uintptr) bool {
		_, opErr = sys.Read(int(fd), buf[:])
		return true
	})
	if err != nil {
		return err
	}
	return opErr
}

// rawSendto sends one byte directly to the connection's fd.
func rawSendto(raw sys.RawConn) error {
	var opErr error
	err := raw.Write(func(fd uintptr) bool {
		opErr = sys.Sendto(int(fd), []byte("x"), sys.MSG_DONTWAIT, &sys.SockaddrInet4{
			Port: 9,
			Addr: [4]byte{127, 0, 0, 1},
		})
		return true
	})
	if err != nil {
		return err
	}
	return opErr
}

// rawRecvfrom receives one byte directly from the connection's fd.
func rawRecvfrom(raw sys.RawConn) error {
	var buf [1]byte
	var opErr error
	err := raw.Read(func(fd uintptr) bool {
		_, _, opErr = sys.Recvfrom(int(fd), buf[:], sys.MSG_DONTWAIT)
		return true
	})
	if err != nil {
		return err
	}
	return opErr
}

// checkEpoll logs the result of a non-blocking epoll_wait.
func (h *hostinetSR) checkEpoll(epollFD int) {
	events := make([]sys.EpollEvent, 1)
	n, err := sys.EpollWait(epollFD, events, 0)
	if err != nil {
		h.logResult("EPOLL_WAIT", err)
		return
	}
	if n == 0 {
		h.logf("EPOLL_WAIT TIMEOUT")
		return
	}
	h.logf("EPOLL_EVENT=0x%x", events[0].Events)
	if events[0].Events&sys.EPOLLERR != 0 {
		h.logf("EPOLL_EVENT_ERR")
		if v, err := sys.GetsockoptInt(int(events[0].Fd), sys.SOL_SOCKET, sys.SO_ERROR); err != nil {
			h.logResult("SO_ERROR_GET", err)
		} else {
			h.logf("SO_ERROR=%d", v)
		}
	}
	if events[0].Events&sys.EPOLLHUP != 0 {
		h.logf("EPOLL_EVENT_HUP")
	}
}

// logResult logs the outcome of op, including the errno on failure.
func (h *hostinetSR) logResult(op string, err error) {
	if err == nil {
		h.logf("%s OK", op)
		return
	}
	if errno, ok := errnoOf(err); ok {
		h.logf("%s ERRNO=%d", op, errno)
		return
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		h.logf("%s TIMEOUT", op)
		return
	}
	h.logf("%s ERR=%q", op, err.Error())
}

// logf appends a line to the output file.
func (h *hostinetSR) logf(format string, args ...any) {
	f, err := os.OpenFile(h.file, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("OpenFile(%q): %v", h.file, err)
	}
	defer f.Close()
	fmt.Fprintf(f, format+"\n", args...)
}

// syscallConner is implemented by connection types that expose their fd.
type syscallConner interface {
	SyscallConn() (sys.RawConn, error)
}

// mustRawConn returns the connection's raw fd accessor.
func (h *hostinetSR) mustRawConn(c syscallConner) sys.RawConn {
	raw, err := c.SyscallConn()
	if err != nil {
		log.Fatalf("SyscallConn: %v", err)
	}
	return raw
}

// errnoOf unwraps the errno from err, if any.
func errnoOf(err error) (sys.Errno, bool) {
	var errno sys.Errno
	if errors.As(err, &errno) {
		return errno, true
	}
	return 0, false
}
