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
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/link/sniffer/pcap"
	"gvisor.dev/gvisor/pkg/usermem"
)

var device = flag.String("device", "", "local device for test packets")

// Sniffer can sniff raw packets on the wire.
type Sniffer struct {
	t    *testing.T
	fd   int
	pcap *os.File
}

func htons(x uint16) uint16 {
	buf := [2]byte{}
	binary.BigEndian.PutUint16(buf[:], x)
	return usermem.ByteOrder.Uint16(buf[:])
}

// NewSniffer creates a Sniffer connected to *device.
func NewSniffer(t *testing.T) (Sniffer, error) {
	flag.Parse()
	snifferFD, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return Sniffer{}, err
	}
	if err := unix.SetsockoptInt(snifferFD, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, 1); err != nil {
		t.Fatalf("can't set sockopt SO_RCVBUFFORCE to 1: %s", err)
	}
	if err := unix.SetsockoptInt(snifferFD, unix.SOL_SOCKET, unix.SO_RCVBUF, 1e7); err != nil {
		t.Fatalf("can't setsockopt SO_RCVBUF to 10M: %s", err)
	}

	pf, err := pcapLogFile(fmt.Sprintf("sniffer_dump_%d.pcap", snifferFD))
	if err != nil {
		return Sniffer{}, err
	}

	return Sniffer{
		t:    t,
		fd:   snifferFD,
		pcap: pf,
	}, nil
}

func pcapLogFile(name string) (*os.File, error) {
	dir, ok := os.LookupEnv("TEST_UNDECLARED_OUTPUTS_DIR")
	if !ok {
		dir = "/tmp"
	}
	pf, err := os.OpenFile(filepath.Join(dir, name), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		return nil, fmt.Errorf("creating pcap file: %s", err)
	}

	h, err := pcap.MakeHeader(pcap.MaxSnaplen)
	if err != nil {
		return nil, fmt.Errorf("making pcap file header: %s", err)
	}
	h.Network = 1 // LINKTYPE_ETHERNET
	if err := binary.Write(pf, binary.BigEndian, h); err != nil {
		return nil, fmt.Errorf("writing to pcap file: %s", err)
	}

	return pf, nil
}

// maxReadSize should be large enough for the maximum frame size in bytes. If a
// packet too large for the buffer arrives, the test will get a fatal error.
const maxReadSize = 65536

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
		buf = buf[:nread]

		writePacket(s.t, s.pcap, buf)

		return buf
	}
}

func writePacket(t *testing.T, f *os.File, buf []byte) {
	t.Helper()

	if f == nil {
		return
	}

	pb := buf
	if len(pb) > pcap.MaxSnaplen {
		pb = pb[:pcap.MaxSnaplen]
	}
	if err := binary.Write(f, binary.BigEndian, pcap.MakePacketHeader(uint32(len(pb)), uint32(len(buf)))); err != nil {
		t.Fatal("can't write packet header to pcap file:", err)
	}

	if _, err := f.Write(pb); err != nil {
		t.Fatal("can't write packet data to pcap file:", err)
	}
}

// Close the socket that Sniffer is using.
func (s *Sniffer) Close() {
	s.pcap.Close()
	if err := unix.Close(s.fd); err != nil {
		s.t.Fatalf("can't close sniffer socket: %s", err)
	}
	s.fd = -1
}

// Injector can inject raw frames.
type Injector struct {
	t    *testing.T
	fd   int
	mtu  int
	pcap *os.File
}

// NewInjector creates a new injector on *device.
func NewInjector(t *testing.T) (Injector, error) {
	flag.Parse()
	ifInfo, err := net.InterfaceByName(*device)
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

	injectFD, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return Injector{}, err
	}
	if err := unix.Bind(injectFD, &sa); err != nil {
		return Injector{}, err
	}

	pf, err := pcapLogFile(fmt.Sprintf("injector_dump_%d.pcap", injectFD))
	if err != nil {
		return Injector{}, err
	}

	return Injector{
		t:    t,
		fd:   injectFD,
		mtu:  ifInfo.MTU,
		pcap: pf,
	}, nil
}

// Send a raw frame.
func (i *Injector) Send(b []byte) {
	if _, err := unix.Write(i.fd, b); err != nil {
		i.t.Fatalf("can't write: %s", err)
	}

	writePacket(i.t, i.pcap, b)
}

// Close the underlying socket.
func (i *Injector) Close() {
	i.pcap.Close()
	if err := unix.Close(i.fd); err != nil {
		i.t.Fatalf("can't close sniffer socket: %s", err)
	}
	i.fd = -1
}
