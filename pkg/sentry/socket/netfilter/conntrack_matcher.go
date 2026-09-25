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

package netfilter

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const matcherNameConntrack = "conntrack"

// supportedMatchFlags contains the XT_CONNTRACK_* flags supported by this matcher.
// Only --ctstate is evaluated; other sub-matches (--ctproto, --ctorigsrc, etc.)
// are rejected during unmarshal so callers do not silently assume they filter.
const supportedMatchFlags = linux.XT_CONNTRACK_STATE | linux.XT_CONNTRACK_STATE_ALIAS

// revisionOffset is the byte offset of the Revision field within a marshalled
// struct xt_entry_match (u16 match_size + [XT_EXTENSION_MAXNAMELEN]byte name +
// u8 revision). It is the last byte of the fixed-size header.
const revisionOffset = linux.SizeOfXTEntryMatch - 1

func init() {
	// iptables (xt_conntrack.so) negotiates the highest revision the kernel
	// reports; kube-proxy's iptables builds use revision 3. Register 1, 2 and
	// 3 so the negotiation succeeds regardless of the userspace version.
	registerMatchMaker(conntrackMarshaler{rev: 1})
	registerMatchMaker(conntrackMarshaler{rev: 2})
	registerMatchMaker(conntrackMarshaler{rev: 3})
}

// conntrackMarshaler implements matchMaker for the "conntrack" match. Only
// --ctstate is interpreted (the sole conntrack sub-match kube-proxy uses); the
// parsed rule bytes are retained verbatim so that iptables-save round-trips.
type conntrackMarshaler struct {
	rev uint8
}

// name implements matchMaker.name.
func (conntrackMarshaler) name() string {
	return matcherNameConntrack
}

// revision implements matchMaker.revision.
func (c conntrackMarshaler) revision() uint8 {
	return c.rev
}

// marshal implements matchMaker.marshal.
func (c conntrackMarshaler) marshal(mr matcher) []byte {
	m := mr.(*conntrackMatcher)
	buf := marshalEntryMatch(matcherNameConntrack, m.raw)
	// marshalEntryMatch leaves Revision at 0; stamp the real revision so that
	// iptables-save reads the match back with the revision it negotiated.
	if len(buf) > revisionOffset {
		buf[revisionOffset] = m.rev
	}
	return buf
}

// unmarshal implements matchMaker.unmarshal. The xt_conntrack_mtinfo struct
// layout differs across revisions (rev1 has a u8 StateMask; rev2/3 widen it to
// u16 and add fields), so parse with the matching ABI struct.
func (c conntrackMarshaler) unmarshal(_ IDMapper, buf []byte, _ stack.IPHeaderFilter) (stack.Matcher, error) {
	m := &conntrackMatcher{rev: c.rev}
	switch c.rev {
	case 1:
		var mt linux.XTConntrackMtinfo
		if len(buf) < mt.SizeBytes() {
			return nil, fmt.Errorf("conntrack rev1: buf too small: %d", len(buf))
		}
		mt.UnmarshalBytes(buf[:mt.SizeBytes()])
		if mt.MatchFlags&^supportedMatchFlags != 0 {
			return nil, fmt.Errorf("conntrack rev1: unsupported match flags 0x%x (only --ctstate is supported)", mt.MatchFlags)
		}
		m.matchFlags, m.invertFlags, m.stateMask = mt.MatchFlags, mt.InvertFlags, uint16(mt.StateMask)
		m.raw = append([]byte(nil), buf[:mt.SizeBytes()]...)
	case 2:
		var mt linux.XTConntrackMtinfo2
		if len(buf) < mt.SizeBytes() {
			return nil, fmt.Errorf("conntrack rev2: buf too small: %d", len(buf))
		}
		mt.UnmarshalBytes(buf[:mt.SizeBytes()])
		if mt.MatchFlags&^supportedMatchFlags != 0 {
			return nil, fmt.Errorf("conntrack rev2: unsupported match flags 0x%x (only --ctstate is supported)", mt.MatchFlags)
		}
		m.matchFlags, m.invertFlags, m.stateMask = mt.MatchFlags, mt.InvertFlags, mt.StateMask
		m.raw = append([]byte(nil), buf[:mt.SizeBytes()]...)
	case 3:
		var mt linux.XTConntrackMtinfo3
		if len(buf) < mt.SizeBytes() {
			return nil, fmt.Errorf("conntrack rev3: buf too small: %d", len(buf))
		}
		mt.UnmarshalBytes(buf[:mt.SizeBytes()])
		if mt.MatchFlags&^supportedMatchFlags != 0 {
			return nil, fmt.Errorf("conntrack rev3: unsupported match flags 0x%x (only --ctstate is supported)", mt.MatchFlags)
		}
		m.matchFlags, m.invertFlags, m.stateMask = mt.MatchFlags, mt.InvertFlags, mt.StateMask
		m.raw = append([]byte(nil), buf[:mt.SizeBytes()]...)
	default:
		return nil, fmt.Errorf("conntrack: unsupported revision %d", c.rev)
	}
	return m, nil
}

// conntrackMatcher matches on the connection-tracking --ctstate of a packet.
type conntrackMatcher struct {
	rev         uint8
	matchFlags  uint16
	invertFlags uint16
	stateMask   uint16
	raw         []byte
}

// name implements matcher.name.
func (*conntrackMatcher) name() string {
	return matcherNameConntrack
}

// revision implements matcher.revision.
func (m *conntrackMatcher) revision() uint8 {
	return m.rev
}

// Match implements stack.Matcher.Match. Only --ctstate is implemented.
func (m *conntrackMatcher) Match(_ stack.Hook, pkt *stack.PacketBuffer, _, _ string) (bool, bool) {
	if m.matchFlags&supportedMatchFlags == 0 {
		return true, false
	}
	matched := packetCtStateBits(pkt)&m.stateMask != 0
	if m.invertFlags&supportedMatchFlags != 0 {
		matched = !matched
	}
	return matched, false
}

// isICMPErrorPacket returns true if the packet buffer contains an ICMP or ICMPv6
// error message (Destination Unreachable, Time Exceeded, Param Problem, etc.).
func isICMPErrorPacket(pkt *stack.PacketBuffer) bool {
	switch pkt.TransportProtocolNumber {
	case header.ICMPv4ProtocolNumber:
		h := header.ICMPv4(pkt.TransportHeader().Slice())
		if len(h) >= header.ICMPv4MinimumSize {
			switch h.Type() {
			case header.ICMPv4DstUnreachable, header.ICMPv4TimeExceeded, header.ICMPv4ParamProblem, header.ICMPv4SrcQuench, header.ICMPv4Redirect:
				return true
			}
		}
	case header.ICMPv6ProtocolNumber:
		h := header.ICMPv6(pkt.TransportHeader().Slice())
		if len(h) >= header.ICMPv6MinimumSize {
			switch h.Type() {
			case header.ICMPv6DstUnreachable, header.ICMPv6PacketTooBig, header.ICMPv6TimeExceeded, header.ICMPv6ParamProblem:
				return true
			}
		}
	}
	return false
}

// packetCtStateBits maps a packet's gVisor conntrack state (and applied NAT) to
// the XT_CONNTRACK_STATE_* bitmask that iptables --ctstate compares against.
func packetCtStateBits(pkt *stack.PacketBuffer) uint16 {
	if !pkt.IsConnTrackConfigured() {
		return linux.XT_CONNTRACK_STATE_INVALID
	}
	// In Linux, ICMP error messages associated with an existing connection
	// evaluate to the RELATED state.
	if isICMPErrorPacket(pkt) {
		return linux.XT_CONNTRACK_STATE_RELATED
	}
	reply := pkt.IsReplyPacket()
	var info stack.ConnTrackInfo
	pkt.FillConnTrackInfo(stack.ConnTrackInfoOpts{FillState: true, UseReplyDir: reply}, &info)
	var bits uint16
	switch info.State {
	case stack.ConnTrackStateNew:
		bits |= linux.XT_CONNTRACK_STATE_NEW
	case stack.ConnTrackStateEstablished, stack.ConnTrackStateEstablishedReply:
		bits |= linux.XT_CONNTRACK_STATE_ESTABLISHED
	case stack.ConnTrackStateRelated:
		bits |= linux.XT_CONNTRACK_STATE_RELATED
	case stack.ConnTrackStateInvalid:
		bits |= linux.XT_CONNTRACK_STATE_INVALID
	default:
		// Non-TCP flows without reply: NEW on first packet, ESTABLISHED once reply seen.
		if reply {
			bits |= linux.XT_CONNTRACK_STATE_ESTABLISHED
		} else {
			bits |= linux.XT_CONNTRACK_STATE_NEW
		}
	}
	if pkt.IsNATConfigured(stack.DNAT) {
		bits |= linux.XT_CONNTRACK_STATE_DNAT
	}
	if pkt.IsNATConfigured(stack.SNAT) {
		bits |= linux.XT_CONNTRACK_STATE_SNAT
	}
	return bits
}
