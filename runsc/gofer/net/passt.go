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
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/google/subcommands"
	"golang.org/x/sys/unix"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/runsc/config"
	egressfilter "gvisor.dev/gvisor/runsc/gofer/net/egressfilter"
	netgoferfilter "gvisor.dev/gvisor/runsc/gofer/net/filter"
)

// passt mode.
//
// In passt mode, netgofer copies packets between the sentry and a passt
// process (https://passt.top). passt opens host sockets on behalf of the
// sandbox. runsc creates a connected SOCK_STREAM socket pair, starts passt with
// one end ("passt -F <fd>") and gives netgofer the other end (--passt-fd).
//
// The sentry side carries raw IP packets, one per SOCK_SEQPACKET message. The
// passt side carries Ethernet frames, each prefixed with its length as a
// 4-byte big-endian integer. netgofer adds and removes the Ethernet header.
//
// netgofer applies the egress filter (the same rules as proxy mode) to each
// packet from the sentry, and drops packets to destinations that the filter
// does not allow. Packets from passt are not filtered.
//
// passt exits when its socket is closed, so passt stops when netgofer stops.

const (
	// passtLenSize is the size of the frame length prefix on the passt socket.
	passtLenSize = 4

	// passtHeaderSize is the size of the length prefix plus the Ethernet header.
	passtHeaderSize = passtLenSize + header.EthernetMinimumSize

	// passtMaxFrameSize is the largest Ethernet frame (without the length
	// prefix) that netgofer sends to or accepts from passt.
	passtMaxFrameSize = 65535

	// passtMaxPacketSize is the largest IP packet that fits in one frame.
	passtMaxPacketSize = passtMaxFrameSize - header.EthernetMinimumSize
)

var (
	// PasstGuestMAC is the source MAC address of frames that netgofer sends to
	// passt on behalf of the sandbox.
	PasstGuestMAC = tcpip.LinkAddress("\x02\x02\x02\x02\x02\x02")

	// PasstMAC is the destination MAC address of frames that netgofer sends to
	// passt. runsc must start passt with the same address ("-M").
	PasstMAC = tcpip.LinkAddress("\x02\x02\x02\x02\x02\x03")
)

// encodePasstFrame turns the IP packet in buf[passtHeaderSize:][:pktLen] into
// a passt frame. It writes the length prefix and Ethernet header into
// buf[:passtHeaderSize] and returns the complete frame. It returns false if
// the packet is not an IPv4 or IPv6 packet, or if it is too large.
func encodePasstFrame(buf []byte, pktLen int) ([]byte, bool) {
	if pktLen <= 0 || pktLen > passtMaxPacketSize || passtHeaderSize+pktLen > len(buf) {
		return nil, false
	}
	pkt := buf[passtHeaderSize:][:pktLen]
	var proto tcpip.NetworkProtocolNumber
	switch header.IPVersion(pkt) {
	case header.IPv4Version:
		proto = header.IPv4ProtocolNumber
	case header.IPv6Version:
		proto = header.IPv6ProtocolNumber
	default:
		return nil, false
	}
	binary.BigEndian.PutUint32(buf[:passtLenSize], uint32(header.EthernetMinimumSize+pktLen))
	header.Ethernet(buf[passtLenSize:]).Encode(&header.EthernetFields{
		SrcAddr: PasstGuestMAC,
		DstAddr: PasstMAC,
		Type:    proto,
	})
	return buf[:passtHeaderSize+pktLen], true
}

// readPasstFrame reads one length-prefixed frame from r into buf. It returns
// io.EOF if r is at the end of the stream before the frame starts.
func readPasstFrame(r io.Reader, buf []byte) ([]byte, error) {
	var lenBuf [passtLenSize]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	frameLen := binary.BigEndian.Uint32(lenBuf[:])
	if frameLen > uint32(len(buf)) {
		return nil, fmt.Errorf("passt frame length %d exceeds maximum %d", frameLen, len(buf))
	}
	frame := buf[:frameLen]
	if _, err := io.ReadFull(r, frame); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return frame, nil
}

// passtFramePayload returns the IP packet in an Ethernet frame from passt. It
// returns false for frames that do not carry IPv4 or IPv6 (for example ARP).
func passtFramePayload(frame []byte) ([]byte, bool) {
	if len(frame) <= header.EthernetMinimumSize {
		return nil, false
	}
	switch header.Ethernet(frame).Type() {
	case header.IPv4ProtocolNumber, header.IPv6ProtocolNumber:
		return frame[header.EthernetMinimumSize:], true
	default:
		return nil, false
	}
}

// passtPacketAllowed reports whether the egress filter f allows the IP packet
// pkt from the sentry. It checks the destination address, and the destination
// port of TCP and UDP packets. Packets without a port (for example ICMP, IP
// fragments after the first, and IPv6 packets with extension headers) get an
// address-only check. Malformed packets are not allowed.
func passtPacketAllowed(f *egressfilter.Filter, pkt []byte) bool {
	var (
		dst      tcpip.Address
		proto    tcpip.TransportProtocolNumber
		payload  []byte
		hasPorts bool
	)
	switch header.IPVersion(pkt) {
	case header.IPv4Version:
		ip := header.IPv4(pkt)
		if !ip.IsValid(len(pkt)) {
			return false
		}
		dst = ip.DestinationAddress()
		proto = ip.TransportProtocol()
		payload = ip.Payload()
		hasPorts = ip.FragmentOffset() == 0
	case header.IPv6Version:
		if len(pkt) < header.IPv6MinimumSize {
			return false
		}
		ip := header.IPv6(pkt)
		dst = ip.DestinationAddress()
		// Extension headers are not parsed. If the next header is not TCP or
		// UDP, the packet gets the address-only check below.
		proto = tcpip.TransportProtocolNumber(ip.NextHeader())
		payload = ip.Payload()
		hasPorts = true
	default:
		return false
	}
	if hasPorts {
		switch proto {
		case header.TCPProtocolNumber:
			if len(payload) < header.TCPMinimumSize {
				return false
			}
			return f.Allows(dst, header.TCP(payload).DestinationPort())
		case header.UDPProtocolNumber:
			if len(payload) < header.UDPMinimumSize {
				return false
			}
			return f.Allows(dst, header.UDP(payload).DestinationPort())
		}
	}
	return f.AllowsAddr(dst)
}

// copySentryToPasst copies packets from the sentry to passt until an error.
// It drops packets that the egress filter f does not allow.
func copySentryToPasst(passt io.Writer, sentry io.Reader, f *egressfilter.Filter) error {
	buf := make([]byte, passtHeaderSize+passtMaxPacketSize)
	for {
		n, err := sentry.Read(buf[passtHeaderSize:])
		if err != nil {
			return err
		}
		if !passtPacketAllowed(f, buf[passtHeaderSize:][:n]) {
			log.Debugf("Dropping %d-byte packet from the sandbox to a disallowed destination", n)
			continue
		}
		frame, ok := encodePasstFrame(buf, n)
		if !ok {
			log.Debugf("Dropping %d-byte non-IP packet from the sandbox", n)
			continue
		}
		if _, err := passt.Write(frame); err != nil {
			return err
		}
	}
}

// copyPasstToSentry copies packets from passt to the sentry until an error.
func copyPasstToSentry(sentry io.Writer, passt io.Reader) error {
	r := bufio.NewReaderSize(passt, passtLenSize+passtMaxFrameSize)
	buf := make([]byte, passtMaxFrameSize)
	for {
		frame, err := readPasstFrame(r, buf)
		if err != nil {
			return err
		}
		pkt, ok := passtFramePayload(frame)
		if !ok {
			continue
		}
		if _, err := sentry.Write(pkt); err != nil {
			if errors.Is(err, unix.EMSGSIZE) || errors.Is(err, unix.ENOBUFS) {
				log.Debugf("Dropping %d-byte packet to the sandbox: %v", len(pkt), err)
				continue
			}
			return err
		}
	}
}

// passtCopyResult is the result of one copy direction.
type passtCopyResult struct {
	fromSentry bool
	err        error
}

// forwardPasst copies packets in both directions until one direction stops,
// then closes both files and waits for the other direction. It returns the
// result of the direction that stopped first. f is the egress filter for
// packets from the sentry.
func forwardPasst(sentry, passt io.ReadWriteCloser, f *egressfilter.Filter) passtCopyResult {
	results := make(chan passtCopyResult, 2)
	go func() {
		results <- passtCopyResult{fromSentry: true, err: copySentryToPasst(passt, sentry, f)}
	}()
	go func() {
		results <- passtCopyResult{fromSentry: false, err: copyPasstToSentry(sentry, passt)}
	}()
	first := <-results
	_ = sentry.Close()
	_ = passt.Close()
	<-results
	return first
}

// newNonblockingFile sets O_NONBLOCK on fd and wraps it in an *os.File, so
// that reads and writes use the Go runtime network poller. The returned file
// owns fd.
func newNonblockingFile(fd int, name string) (*os.File, error) {
	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, fmt.Errorf("setting O_NONBLOCK on %s FD %d: %w", name, fd, err)
	}
	return os.NewFile(uintptr(fd), name), nil
}

// runPasstMode copies packets between the sentry (n.udsFD) and passt
// (n.passtFD) until either side closes its socket.
func (n *Netgofer) runPasstMode(conf *config.Config) subcommands.ExitStatus {
	log.Infof("Running in passt mode")

	// Set up both files before seccomp is installed.
	sentry, err := newNonblockingFile(n.udsFD, "uds")
	if err != nil {
		_ = unix.Close(n.udsFD)
		_ = unix.Close(n.passtFD)
		log.Warningf("Failed to set up sandbox socket: %v", err)
		return subcommands.ExitFailure
	}
	defer sentry.Close()
	passt, err := newNonblockingFile(n.passtFD, "passt")
	if err != nil {
		_ = unix.Close(n.passtFD)
		log.Warningf("Failed to set up passt socket: %v", err)
		return subcommands.ExitFailure
	}
	defer passt.Close()

	// The filter reads the host interface addresses over netlink, which the
	// seccomp filters do not allow, so create it first.
	if n.egressFilter == nil {
		f, err := egressfilter.New(egressfilter.Options{})
		if err != nil {
			log.Warningf("Failed to initialize egress filter: %v", err)
			return subcommands.ExitFailure
		}
		n.egressFilter = f
	}

	if !n.disableSeccomp {
		if err := netgoferfilter.Install(netgoferfilter.Options{
			ProfileEnabled: conf.ProfileEnable || n.profileEnabled,
			CgoEnabled:     config.CgoEnabled,
		}); err != nil {
			log.Warningf("Failed to install seccomp filters: %v", err)
			return subcommands.ExitFailure
		}
	}

	log.Infof("Passt forwarding started")
	if n.ready != nil {
		close(n.ready)
	}

	res := forwardPasst(sentry, passt, n.egressFilter)
	if res.fromSentry && (errors.Is(res.err, io.EOF) || errors.Is(res.err, unix.ECONNRESET)) {
		log.Infof("UDS socket peer closed (Sandbox exited). Proxy exiting...")
		return subcommands.ExitSuccess
	}
	if res.fromSentry {
		log.Warningf("Reading from the sandbox socket failed: %v", res.err)
	} else {
		log.Warningf("passt connection stopped: %v", res.err)
	}
	return subcommands.ExitFailure
}
