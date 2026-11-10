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

package net

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/subcommands"
	"golang.org/x/sys/unix"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/runsc/config"
	egressfilter "gvisor.dev/gvisor/runsc/gofer/net/egressfilter"
)

// testIPv4Pkt returns an IPv4 packet from the sandbox to dst with the given
// transport protocol, transport header and payload (l4), and fragment offset.
func testIPv4Pkt(dst [4]byte, proto tcpip.TransportProtocolNumber, l4 []byte, fragOffset uint16) []byte {
	pkt := make([]byte, header.IPv4MinimumSize+len(l4))
	header.IPv4(pkt).Encode(&header.IPv4Fields{
		TotalLength:    uint16(len(pkt)),
		TTL:            64,
		Protocol:       uint8(proto),
		FragmentOffset: fragOffset,
		SrcAddr:        tcpip.AddrFrom4([4]byte{10, 0, 2, 15}),
		DstAddr:        tcpip.AddrFrom4(dst),
	})
	copy(pkt[header.IPv4MinimumSize:], l4)
	return pkt
}

// testUDP returns a UDP header and payload to port.
func testUDP(port uint16, payload string) []byte {
	b := make([]byte, header.UDPMinimumSize+len(payload))
	header.UDP(b).Encode(&header.UDPFields{SrcPort: 40000, DstPort: port, Length: uint16(len(b))})
	copy(b[header.UDPMinimumSize:], payload)
	return b
}

// testTCP returns a TCP header to port.
func testTCP(port uint16) []byte {
	b := make([]byte, header.TCPMinimumSize)
	header.TCP(b).Encode(&header.TCPFields{SrcPort: 40000, DstPort: port, DataOffset: header.TCPMinimumSize, Flags: header.TCPFlagSyn})
	return b
}

// testIPv4Packet returns an IPv4 UDP packet to 8.8.8.8:53, which the egress
// filter allows.
func testIPv4Packet(payload string) []byte {
	return testIPv4Pkt([4]byte{8, 8, 8, 8}, header.UDPProtocolNumber, testUDP(53, payload), 0)
}

// testIPv6Packet returns a fake IPv6 packet.
func testIPv6Packet(payload string) []byte {
	pkt := make([]byte, header.IPv6MinimumSize, header.IPv6MinimumSize+len(payload))
	pkt[0] = 0x60
	return append(pkt, payload...)
}

// testPasstFrame returns pkt as a length-prefixed Ethernet frame from passt.
func testPasstFrame(proto tcpip.NetworkProtocolNumber, pkt []byte) []byte {
	frame := make([]byte, passtHeaderSize+len(pkt))
	binary.BigEndian.PutUint32(frame, uint32(header.EthernetMinimumSize+len(pkt)))
	header.Ethernet(frame[passtLenSize:]).Encode(&header.EthernetFields{
		SrcAddr: PasstMAC,
		DstAddr: PasstGuestMAC,
		Type:    proto,
	})
	copy(frame[passtHeaderSize:], pkt)
	return frame
}

func TestEncodePasstFrame(t *testing.T) {
	for _, tc := range []struct {
		name      string
		pkt       []byte
		wantOK    bool
		wantProto tcpip.NetworkProtocolNumber
	}{
		{name: "ipv4", pkt: testIPv4Packet("v4"), wantOK: true, wantProto: header.IPv4ProtocolNumber},
		{name: "ipv6", pkt: testIPv6Packet("v6"), wantOK: true, wantProto: header.IPv6ProtocolNumber},
		{name: "not IP", pkt: []byte{0x10, 1, 2, 3}},
		{name: "empty", pkt: nil},
		{name: "too large", pkt: append([]byte{0x45}, make([]byte, passtMaxPacketSize)...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buf := make([]byte, passtHeaderSize+len(tc.pkt))
			copy(buf[passtHeaderSize:], tc.pkt)
			frame, ok := encodePasstFrame(buf, len(tc.pkt))
			if ok != tc.wantOK {
				t.Fatalf("encodePasstFrame() ok = %t, want %t", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if got, want := binary.BigEndian.Uint32(frame), uint32(header.EthernetMinimumSize+len(tc.pkt)); got != want {
				t.Errorf("length prefix = %d, want %d", got, want)
			}
			eth := header.Ethernet(frame[passtLenSize:])
			if got := eth.SourceAddress(); got != PasstGuestMAC {
				t.Errorf("source MAC = %s, want %s", got, PasstGuestMAC)
			}
			if got := eth.DestinationAddress(); got != PasstMAC {
				t.Errorf("destination MAC = %s, want %s", got, PasstMAC)
			}
			if got := eth.Type(); got != tc.wantProto {
				t.Errorf("EtherType = %#x, want %#x", got, tc.wantProto)
			}
			if got := frame[passtHeaderSize:]; !bytes.Equal(got, tc.pkt) {
				t.Errorf("payload = %x, want %x", got, tc.pkt)
			}
		})
	}
}

func TestPasstFramePayload(t *testing.T) {
	v4 := testIPv4Packet("v4")
	v6 := testIPv6Packet("v6")
	for _, tc := range []struct {
		name   string
		frame  []byte
		want   []byte
		wantOK bool
	}{
		{name: "ipv4", frame: testPasstFrame(header.IPv4ProtocolNumber, v4)[passtLenSize:], want: v4, wantOK: true},
		{name: "ipv6", frame: testPasstFrame(header.IPv6ProtocolNumber, v6)[passtLenSize:], want: v6, wantOK: true},
		{name: "arp", frame: testPasstFrame(header.ARPProtocolNumber, make([]byte, header.ARPSize))[passtLenSize:]},
		{name: "header only", frame: testPasstFrame(header.IPv4ProtocolNumber, nil)[passtLenSize:]},
		{name: "short", frame: []byte{1, 2, 3}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := passtFramePayload(tc.frame)
			if ok != tc.wantOK || !bytes.Equal(got, tc.want) {
				t.Errorf("passtFramePayload() = %x, %t; want %x, %t", got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

func TestReadPasstFrame(t *testing.T) {
	pkt := testIPv4Packet("hello")
	frame := testPasstFrame(header.IPv4ProtocolNumber, pkt)

	t.Run("two frames", func(t *testing.T) {
		r := bytes.NewReader(append(append([]byte{}, frame...), frame...))
		buf := make([]byte, passtMaxFrameSize)
		for i := 0; i < 2; i++ {
			got, err := readPasstFrame(r, buf)
			if err != nil {
				t.Fatalf("readPasstFrame() #%d failed: %v", i, err)
			}
			if !bytes.Equal(got, frame[passtLenSize:]) {
				t.Fatalf("readPasstFrame() #%d = %x, want %x", i, got, frame[passtLenSize:])
			}
		}
		if _, err := readPasstFrame(r, buf); err != io.EOF {
			t.Errorf("readPasstFrame() at end = %v, want io.EOF", err)
		}
	})
	t.Run("truncated", func(t *testing.T) {
		r := bytes.NewReader(frame[:len(frame)-1])
		if _, err := readPasstFrame(r, make([]byte, passtMaxFrameSize)); err != io.ErrUnexpectedEOF {
			t.Errorf("readPasstFrame() = %v, want io.ErrUnexpectedEOF", err)
		}
	})
	t.Run("too large", func(t *testing.T) {
		r := bytes.NewReader(frame)
		if _, err := readPasstFrame(r, make([]byte, 8)); err == nil {
			t.Error("readPasstFrame() with a small buffer succeeded, want error")
		}
	})
}

// passtTestPeers holds the test side of the two netgofer sockets.
type passtTestPeers struct {
	// sentry is the sandbox end of the SOCK_SEQPACKET pair.
	sentry *os.File
	// passt is the passt end of the SOCK_STREAM pair.
	passt *os.File
}

// newPasstSocketPairs creates the two socket pairs used in passt mode. It
// returns the netgofer FDs and the test peers.
func newPasstSocketPairs(t *testing.T) (udsFD, passtFD int, peers passtTestPeers) {
	t.Helper()
	seq, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("unix.Socketpair(SOCK_SEQPACKET) failed: %v", err)
	}
	stream, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("unix.Socketpair(SOCK_STREAM) failed: %v", err)
	}
	sentry, err := newNonblockingFile(seq[1], "test-sentry")
	if err != nil {
		t.Fatalf("newNonblockingFile() failed: %v", err)
	}
	passt, err := newNonblockingFile(stream[1], "test-passt")
	if err != nil {
		t.Fatalf("newNonblockingFile() failed: %v", err)
	}
	t.Cleanup(func() {
		_ = sentry.Close()
		_ = passt.Close()
	})
	return seq[0], stream[0], passtTestPeers{sentry: sentry, passt: passt}
}

// readWithTimeout reads once from f with a 5 second deadline.
func readWithTimeout(t *testing.T, f *os.File, buf []byte) (int, error) {
	t.Helper()
	if err := f.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline() failed: %v", err)
	}
	return f.Read(buf)
}

// verifyPasstRoundTrip sends one packet in each direction through netgofer.
func verifyPasstRoundTrip(t *testing.T, peers passtTestPeers) {
	t.Helper()

	// Sandbox to passt: netgofer adds the length prefix and Ethernet header.
	out := testIPv4Packet("from sandbox")
	if _, err := peers.sentry.Write(out); err != nil {
		t.Fatalf("writing to the sandbox socket failed: %v", err)
	}
	if err := peers.passt.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline() failed: %v", err)
	}
	frame, err := readPasstFrame(peers.passt, make([]byte, passtMaxFrameSize))
	if err != nil {
		t.Fatalf("reading a frame from netgofer failed: %v", err)
	}
	eth := header.Ethernet(frame)
	if eth.Type() != header.IPv4ProtocolNumber || eth.DestinationAddress() != PasstMAC || eth.SourceAddress() != PasstGuestMAC {
		t.Errorf("frame header = {src %s, dst %s, type %#x}, want {src %s, dst %s, type %#x}",
			eth.SourceAddress(), eth.DestinationAddress(), eth.Type(), PasstGuestMAC, PasstMAC, header.IPv4ProtocolNumber)
	}
	if got := frame[header.EthernetMinimumSize:]; !bytes.Equal(got, out) {
		t.Errorf("frame payload = %x, want %x", got, out)
	}

	// passt to sandbox: netgofer drops the ARP frame and removes the header
	// from the IPv6 frame.
	in := testIPv6Packet("from passt")
	var stream []byte
	stream = append(stream, testPasstFrame(header.ARPProtocolNumber, make([]byte, header.ARPSize))...)
	stream = append(stream, testPasstFrame(header.IPv6ProtocolNumber, in)...)
	if _, err := peers.passt.Write(stream); err != nil {
		t.Fatalf("writing to the passt socket failed: %v", err)
	}
	buf := make([]byte, passtMaxFrameSize)
	n, err := readWithTimeout(t, peers.sentry, buf)
	if err != nil {
		t.Fatalf("reading a packet from netgofer failed: %v", err)
	}
	if got := buf[:n]; !bytes.Equal(got, in) {
		t.Errorf("packet to the sandbox = %x, want %x", got, in)
	}
}

// startInProcessPasst runs runPasstMode in a goroutine without seccomp.
func startInProcessPasst(t *testing.T) (passtTestPeers, <-chan subcommands.ExitStatus) {
	t.Helper()
	udsFD, passtFD, peers := newPasstSocketPairs(t)
	n := &Netgofer{
		udsFD:          udsFD,
		passtFD:        passtFD,
		disableSeccomp: true,
		ready:          make(chan struct{}),
	}
	exit := make(chan subcommands.ExitStatus, 1)
	go func() {
		exit <- n.runPasstMode(&config.Config{})
	}()
	select {
	case <-n.ready:
	case status := <-exit:
		t.Fatalf("runPasstMode() exited early with status %v", status)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for runPasstMode() to become ready")
	}
	return peers, exit
}

func waitForExit(t *testing.T, exit <-chan subcommands.ExitStatus) subcommands.ExitStatus {
	t.Helper()
	select {
	case status := <-exit:
		return status
	case <-time.After(5 * time.Second):
		t.Fatal("runPasstMode() did not exit")
		return subcommands.ExitFailure
	}
}

func TestRunPasstModeSandboxCloses(t *testing.T) {
	peers, exit := startInProcessPasst(t)
	verifyPasstRoundTrip(t, peers)

	// The sandbox exits: netgofer must exit and close the passt socket, so
	// that passt exits too.
	_ = peers.sentry.Close()
	if status := waitForExit(t, exit); status != subcommands.ExitSuccess {
		t.Errorf("runPasstMode() = %v, want %v", status, subcommands.ExitSuccess)
	}
	n, err := readWithTimeout(t, peers.passt, make([]byte, 16))
	if n != 0 || err != io.EOF {
		t.Errorf("read from the passt peer = %d, %v; want 0, io.EOF", n, err)
	}
}

func TestRunPasstModePasstCloses(t *testing.T) {
	peers, exit := startInProcessPasst(t)

	// passt exits: netgofer must exit and close the sandbox socket.
	_ = peers.passt.Close()
	if status := waitForExit(t, exit); status != subcommands.ExitFailure {
		t.Errorf("runPasstMode() = %v, want %v", status, subcommands.ExitFailure)
	}
	n, err := readWithTimeout(t, peers.sentry, make([]byte, 16))
	if n != 0 || err != io.EOF {
		t.Errorf("read from the sandbox peer = %d, %v; want 0, io.EOF", n, err)
	}
}

func TestPasstPacketAllowed(t *testing.T) {
	hostIP := net.IPv4(192, 0, 2, 7)
	f, err := egressfilter.New(egressfilter.Options{LocalAddrs: []net.IP{hostIP}})
	if err != nil {
		t.Fatalf("egressfilter.New() failed: %v", err)
	}
	public := [4]byte{8, 8, 8, 8}
	metadata := [4]byte{169, 254, 169, 254}
	icmp := make([]byte, header.ICMPv4MinimumSize)
	ipv6TCP := make([]byte, header.IPv6MinimumSize+header.TCPMinimumSize)
	header.IPv6(ipv6TCP).Encode(&header.IPv6Fields{
		PayloadLength:     header.TCPMinimumSize,
		TransportProtocol: header.TCPProtocolNumber,
		HopLimit:          64,
		DstAddr:           tcpip.AddrFrom16([16]byte{0xfe, 0x80, 15: 1}),
	})
	copy(ipv6TCP[header.IPv6MinimumSize:], testTCP(80))
	for _, tc := range []struct {
		name string
		pkt  []byte
		want bool
	}{
		{name: "tcp public", pkt: testIPv4Pkt(public, header.TCPProtocolNumber, testTCP(443), 0), want: true},
		{name: "udp public", pkt: testIPv4Pkt(public, header.UDPProtocolNumber, testUDP(53, "q"), 0), want: true},
		{name: "icmp public", pkt: testIPv4Pkt(public, header.ICMPv4ProtocolNumber, icmp, 0), want: true},
		{name: "tcp metadata server", pkt: testIPv4Pkt(metadata, header.TCPProtocolNumber, testTCP(80), 0)},
		{name: "icmp metadata server", pkt: testIPv4Pkt(metadata, header.ICMPv4ProtocolNumber, icmp, 0)},
		{name: "fragment metadata server", pkt: testIPv4Pkt(metadata, header.TCPProtocolNumber, []byte("data"), 8)},
		{name: "fragment public", pkt: testIPv4Pkt(public, header.TCPProtocolNumber, []byte("data"), 8), want: true},
		{name: "tcp host IP", pkt: testIPv4Pkt([4]byte{192, 0, 2, 7}, header.TCPProtocolNumber, testTCP(22), 0)},
		{name: "tcp loopback", pkt: testIPv4Pkt([4]byte{127, 0, 0, 1}, header.TCPProtocolNumber, testTCP(80), 0)},
		{name: "udp port 0", pkt: testIPv4Pkt(public, header.UDPProtocolNumber, testUDP(0, "q"), 0)},
		{name: "udp broadcast", pkt: testIPv4Pkt([4]byte{255, 255, 255, 255}, header.UDPProtocolNumber, testUDP(67, "q"), 0)},
		{name: "truncated tcp", pkt: testIPv4Pkt(public, header.TCPProtocolNumber, make([]byte, 4), 0)},
		{name: "bad ipv4 header", pkt: append([]byte{0x45}, make([]byte, 19)...)},
		{name: "ipv6 tcp link local", pkt: ipv6TCP},
		{name: "not IP", pkt: []byte{0x10, 1, 2, 3}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := passtPacketAllowed(f, tc.pkt); got != tc.want {
				t.Errorf("passtPacketAllowed() = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestRunPasstModeDropsDisallowed(t *testing.T) {
	peers, exit := startInProcessPasst(t)

	// netgofer must drop the packet to the metadata server and forward the
	// next, allowed packet.
	blocked := testIPv4Pkt([4]byte{169, 254, 169, 254}, header.TCPProtocolNumber, testTCP(80), 0)
	allowed := testIPv4Packet("allowed")
	for _, pkt := range [][]byte{blocked, allowed} {
		if _, err := peers.sentry.Write(pkt); err != nil {
			t.Fatalf("writing to the sandbox socket failed: %v", err)
		}
	}
	if err := peers.passt.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline() failed: %v", err)
	}
	frame, err := readPasstFrame(peers.passt, make([]byte, passtMaxFrameSize))
	if err != nil {
		t.Fatalf("reading a frame from netgofer failed: %v", err)
	}
	if got := frame[header.EthernetMinimumSize:]; !bytes.Equal(got, allowed) {
		t.Errorf("first frame payload = %x, want the allowed packet %x", got, allowed)
	}

	_ = peers.sentry.Close()
	if status := waitForExit(t, exit); status != subcommands.ExitSuccess {
		t.Errorf("runPasstMode() = %v, want %v", status, subcommands.ExitSuccess)
	}
}

func TestRunPasstModeBadFrameLength(t *testing.T) {
	peers, exit := startInProcessPasst(t)

	// A length prefix larger than any valid frame means that the stream is
	// out of sync. netgofer must stop.
	var lenBuf [passtLenSize]byte
	binary.BigEndian.PutUint32(lenBuf[:], passtMaxFrameSize+1)
	if _, err := peers.passt.Write(lenBuf[:]); err != nil {
		t.Fatalf("writing to the passt socket failed: %v", err)
	}
	if status := waitForExit(t, exit); status != subcommands.ExitFailure {
		t.Errorf("runPasstMode() = %v, want %v", status, subcommands.ExitFailure)
	}
}

// waitForStartupGoroutines waits until goroutines that some test binaries
// start at process startup have finished. For example, google3 test binaries
// run toollog.SyslogOnStart, which calls getuid(2). The netgofer seccomp
// filter does not allow getuid, so the child would be killed if that goroutine
// ran after the filter is installed. A goroutine that has not run yet shows
// only its wrapper (toollog.Init.gowrap1), so match on the package name.
func waitForStartupGoroutines() {
	buf := make([]byte, 1<<20)
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		n := runtime.Stack(buf, true /* all */)
		if !strings.Contains(string(buf[:n]), "/toollog.") {
			return
		}
	}
}

func TestRunPasstModeWithSeccomp(t *testing.T) {
	if os.Getenv("NETGOFER_PASST_SECCOMP_CHILD") == "1" {
		log.SetLevel(log.Info)
		waitForStartupGoroutines()
		n := &Netgofer{
			udsFD:   3,
			passtFD: 4,
		}
		os.Exit(int(n.runPasstMode(&config.Config{})))
	}

	udsFD, passtFD, peers := newPasstSocketPairs(t)
	udsFile := os.NewFile(uintptr(udsFD), "uds")
	passtFile := os.NewFile(uintptr(passtFD), "passt")
	cmd := exec.Command(os.Args[0], "-test.run=^TestRunPasstModeWithSeccomp$")
	cmd.Env = append(os.Environ(), "NETGOFER_PASST_SECCOMP_CHILD=1", "GOTRACEBACK=system")
	cmd.ExtraFiles = []*os.File{udsFile, passtFile}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Start()
	_ = udsFile.Close()
	_ = passtFile.Close()
	if err != nil {
		t.Fatalf("cmd.Start() failed: %v", err)
	}
	waited := false
	t.Cleanup(func() {
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
		if t.Failed() {
			t.Logf("seccomp child state: %v; output:\n%s", cmd.ProcessState, out.String())
		}
	})

	// Packets wait in the socket buffers until the child reads them, so no
	// ready signal is needed. The child reads them after it installs seccomp.
	verifyPasstRoundTrip(t, peers)

	_ = peers.sentry.Close()
	waited = true
	if err := cmd.Wait(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			t.Fatalf("seccomp child exited with %v; output:\n%s", err, out.String())
		}
		t.Fatalf("cmd.Wait() failed: %v", err)
	}
}
