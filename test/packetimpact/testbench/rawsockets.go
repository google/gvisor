// Copyright 2020 The gVisor Authors.
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

package testbench

import (
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/usermem"
)

// Sniffer can sniff raw packets on the wire.
type Sniffer struct {
	t  *testing.T
	fd int
}

func htons(x uint16) uint16 {
	buf := [2]byte{}
	binary.BigEndian.PutUint16(buf[:], x)
	return usermem.ByteOrder.Uint16(buf[:])
}

// NewSniffer creates a Sniffer connected to *device.
func NewSniffer(t *testing.T) (Sniffer, error) {
	snifferFd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return Sniffer{}, err
	}
	if err := unix.SetsockoptInt(snifferFd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, 1); err != nil {
		t.Fatalf("can't set sockopt SO_RCVBUFFORCE to 1: %s", err)
	}
	if err := unix.SetsockoptInt(snifferFd, unix.SOL_SOCKET, unix.SO_RCVBUF, 1e7); err != nil {
		t.Fatalf("can't setsockopt SO_RCVBUF to 10M: %s", err)
	}
	return Sniffer{
		t:  t,
		fd: snifferFd,
	}, nil
}

// maxReadSize should be large enough for the maximum frame size in bytes. If a
// packet too large for the buffer arrives, the test will get a fatal error.
const maxReadSize int = 65536

// Recv tries to read one frame until the timeout is up.
func (s *Sniffer) Recv(timeout time.Duration) []byte {
	deadline := time.Now().Add(timeout)
	for {
		timeout = deadline.Sub(time.Now())
		if timeout <= 0 {
			return nil
		}
		whole, frac := math.Modf(timeout.Seconds())
		tv := unix.Timeval{
			Sec:  int64(whole),
			Usec: int64(frac * float64(time.Microsecond/time.Second)),
		}

		if err := unix.SetsockoptTimeval(s.fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
			s.t.Fatalf("can't setsockopt SO_RCVTIMEO: %s", err)
		}

		buf := make([]byte, maxReadSize)
		nread, _, err := unix.Recvfrom(s.fd, buf, unix.MSG_TRUNC)
		if err == unix.EINTR || err == unix.EAGAIN {
			// There was a timeout.
			continue
		}
		if err != nil {
			s.t.Fatalf("can't read: %s", err)
		}
		if nread > maxReadSize {
			s.t.Fatalf("received a truncated frame of %d bytes", nread)
		}
		return buf[:nread]
	}
}

// Drain drains the Sniffer's socket receive buffer by receiving until there's
// nothing else to receive.
func (s *Sniffer) Drain() {
	s.t.Helper()
	flags, err := unix.FcntlInt(uintptr(s.fd), unix.F_GETFL, 0)
	if err != nil {
		s.t.Fatalf("failed to get sniffer socket fd flags: %s", err)
	}
	if _, err := unix.FcntlInt(uintptr(s.fd), unix.F_SETFL, flags|unix.O_NONBLOCK); err != nil {
		s.t.Fatalf("failed to make sniffer socket non-blocking: %s", err)
	}
	for {
		buf := make([]byte, maxReadSize)
		_, _, err := unix.Recvfrom(s.fd, buf, unix.MSG_TRUNC)
		if err == unix.EINTR || err == unix.EAGAIN || err == unix.EWOULDBLOCK {
			break
		}
	}
	if _, err := unix.FcntlInt(uintptr(s.fd), unix.F_SETFL, flags); err != nil {
		s.t.Fatalf("failed to restore sniffer socket fd flags: %s", err)
	}
}

// close the socket that Sniffer is using.
func (s *Sniffer) close() error {
	if err := unix.Close(s.fd); err != nil {
		return fmt.Errorf("can't close sniffer socket: %w", err)
	}
	s.fd = -1
	return nil
}

// Injector can inject raw frames.
type Injector struct {
	t  *testing.T
	fd int
}

// NewInjector creates a new injector on *device.
func NewInjector(t *testing.T) (Injector, error) {
	ifInfo, err := net.InterfaceByName(Device)
	if err != nil {
		return Injector{}, err
	}

	var haddr [8]byte
	copy(haddr[:], ifInfo.HardwareAddr)
	sa := unix.SockaddrLinklayer{
		Protocol: unix.ETH_P_IP,
		Ifindex:  ifInfo.Index,
		Halen:    uint8(len(ifInfo.HardwareAddr)),
		Addr:     haddr,
	}

	injectFd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return Injector{}, err
	}
	if err := unix.Bind(injectFd, &sa); err != nil {
		return Injector{}, err
	}
	return Injector{
		t:  t,
		fd: injectFd,
	}, nil
}

// Send a raw frame.
func (i *Injector) Send(b []byte) {
	if _, err := unix.Write(i.fd, b); err != nil {
		i.t.Fatalf("can't write: %s of len %d", err, len(b))
	}
}

// close the underlying socket.
func (i *Injector) close() error {
	if err := unix.Close(i.fd); err != nil {
		return fmt.Errorf("can't close sniffer socket: %w", err)
	}
	i.fd = -1
	return nil
}
