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
	"flag"
	"math"
	"net"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/usermem"
)

var device = flag.String("device", "", "local device for test packets")

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
	flag.Parse()
	snifferFd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return Sniffer{}, err
	}
	return Sniffer{
		t:  t,
		fd: snifferFd,
	}, nil
}

// maxReadSize should be at least 1 more than the maximum frame szie in bytes.
// If a packet too large for the buffer arrives, the test will get a fatal
// error.
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
		nread, err := unix.Read(s.fd, buf)
		if err == unix.EINTR || err == unix.EAGAIN {
			// There was a timeout.
			continue
		}
		if err != nil {
			s.t.Fatalf("can't read: %s", err)
		}
		if nread >= maxReadSize {
			// Either we received exactly maxReadSize bytes or, more likely, the packet was truncated.
			s.t.Fatalf("received a frame of %d bytes that may have been truncated", nread)
		}
		return buf[:nread]
	}
}

// Close the socket that Sniffer is using.
func (s *Sniffer) Close() {
	if err := unix.Close(s.fd); err != nil {
		s.t.Fatalf("can't close sniffer socket: %s", err)
	}
}

// Injector can inject raw frames.
type Injector struct {
	t  *testing.T
	fd int
}

// NewInjector creates a new injector on *device.
func NewInjector(t *testing.T) (Injector, error) {
	flag.Parse()
	ifInfo, err := net.InterfaceByName(*device)
	if err != nil {
		return Injector{}, err
	}

	var haddr [8]byte
	copy(haddr[0:7], ifInfo.HardwareAddr[0:7])
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
		i.t.Fatalf("can't write: %s", err)
	}
}

// Close the underlying socket.
func (i *Injector) Close() {
	if err := unix.Close(i.fd); err != nil {
		i.t.Fatalf("can't close sniffer socket: %s", err)
	}
}
