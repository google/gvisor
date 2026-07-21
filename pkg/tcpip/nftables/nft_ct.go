// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package nftables

import (
	"encoding/binary"
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/socket/netlink/nlmsg"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	// Ref: include/net/netfilter/nf_conntrack_labels.h:NF_CT_LABELS_MAX_SIZE
	ctLabelsMaxSizeBytes = 16
	// Ref: include/net/netfilter/nf_conntrack_helper.h:NF_CT_HELPER_NAME_LEN
	ctHelperNameLen = 16
)

// ctKey is the key that determines the data to retrieve.
type ctKey int

// ctKeyStrings represents the string representation of the key.
var ctKeyStrings = [...]string{
	linux.NFT_CT_STATE:      "NFT_CT_STATE",
	linux.NFT_CT_DIRECTION:  "NFT_CT_DIRECTION",
	linux.NFT_CT_STATUS:     "NFT_CT_STATUS",
	linux.NFT_CT_MARK:       "NFT_CT_MARK",
	linux.NFT_CT_SECMARK:    "NFT_CT_SECMARK",
	linux.NFT_CT_EXPIRATION: "NFT_CT_EXPIRATION",
	linux.NFT_CT_HELPER:     "NFT_CT_HELPER",
	linux.NFT_CT_L3PROTOCOL: "NFT_CT_L3PROTOCOL",
	linux.NFT_CT_SRC:        "NFT_CT_SRC",
	linux.NFT_CT_DST:        "NFT_CT_DST",
	linux.NFT_CT_PROTOCOL:   "NFT_CT_PROTOCOL",
	linux.NFT_CT_PROTO_SRC:  "NFT_CT_PROTO_SRC",
	linux.NFT_CT_PROTO_DST:  "NFT_CT_PROTO_DST",
	linux.NFT_CT_LABELS:     "NFT_CT_LABELS",
	linux.NFT_CT_PKTS:       "NFT_CT_PKTS",
	linux.NFT_CT_BYTES:      "NFT_CT_BYTES",
	linux.NFT_CT_AVGPKT:     "NFT_CT_AVGPKT",
	linux.NFT_CT_ZONE:       "NFT_CT_ZONE",
	linux.NFT_CT_EVENTMASK:  "NFT_CT_EVENTMASK",
	linux.NFT_CT_SRC_IP:     "NFT_CT_SRC_IP",
	linux.NFT_CT_DST_IP:     "NFT_CT_DST_IP",
	linux.NFT_CT_SRC_IP6:    "NFT_CT_SRC_IP6",
	linux.NFT_CT_DST_IP6:    "NFT_CT_DST_IP6",
	linux.NFT_CT_ID:         "NFT_CT_ID",
}

func (k ctKey) String() string {
	if int(k) >= 0 && int(k) < len(ctKeyStrings) {
		return ctKeyStrings[k]
	}
	return "UNKNOWN_CT_KEY"
}

// ctGet loads conntrack data into a register.
type ctGet struct {
	// key is the key to query conntrack for.
	key uint32
	// dregIdx is the index of the destination register in registerSet.data.
	dregIdx int
	// dir is the reply or original direction.
	dir uint8
	// len is the length of data to copy.
	len int
}

// ctSet sets data from a register.
type ctSet struct {
	// key is the key to set data for.
	key uint32
	// sregIdx is the index of the source register in registerSet.data.
	sregIdx int
	// dir is the reply or original direction.
	dir uint8
	// len is the length of data to copy.
	len int
}

// ctInfoOpts returns the ConntrackInfoOpts for the current operation.
func (op *ctGet) ctInfoOpts(pkt *stack.PacketBuffer) stack.ConnTrackInfoOpts {
	opts := stack.ConnTrackInfoOpts{}
	switch op.dir {
	case linux.IP_CT_DIR_ORIGINAL:
		opts.UseReplyDir = false
	case linux.IP_CT_DIR_REPLY:
		opts.UseReplyDir = true
	default:
		opts.UseReplyDir = pkt.IsReplyPacket()
	}
	switch op.key {
	case linux.NFT_CT_ID:
		opts.FillPseudoID = true
	case linux.NFT_CT_EXPIRATION:
		opts.FillExpiration = true
	case linux.NFT_CT_STATE:
		opts.FillState = true
	}
	return opts
}

// netProtoToNFProto converts a tcpip.NetworkProtocolNumber to a Linux NFPROTO constant.
func netProtoToNFProto(proto tcpip.NetworkProtocolNumber) uint8 {
	switch proto {
	case header.IPv4ProtocolNumber:
		return linux.NFPROTO_IPV4
	case header.IPv6ProtocolNumber:
		return linux.NFPROTO_IPV6
	default:
		return linux.NFPROTO_UNSPEC
	}
}

// ctStateToNFTState converts a ConnTrackState to a NFTables state.
// Ref: include/uapi/linux/netfilter/nf_conntrack_common.h:NF_CT_STATE_BIT
func ctStateToNFTState(ctState stack.ConnTrackState) uint32 {
	switch ctState {
	case stack.ConnTrackStateInvalid:
		return linux.NF_CT_STATE_INVALID_BIT
	case stack.ConnTrackStateEstablished:
		return 1 << 1
	case stack.ConnTrackStateEstablishedReply:
		return 1 << 1
	case stack.ConnTrackStateNew:
		return 1 << 3
	default:
		return 0
	}
}

// evaluate implements the operation interface.
// Ref: net/netfilter/nft_ct.c:nft_ct_get_eval()
func (op *ctGet) evaluate(regs *registerSet, evalCtx opEvalCtx) {
	pkt := evalCtx.pkt
	var ctInfo stack.ConnTrackInfo
	ctOk := pkt.FillConnTrackInfo(op.ctInfoOpts(pkt), &ctInfo)
	start := op.dregIdx
	end := op.dregIdx + op.len

	if !ctOk {
		// TODO: b/531808852 - Support notrack conntrack state.
		if op.key == linux.NFT_CT_STATE {
			// If conntrack is not enabled or failed, state is INVALID.
			binary.NativeEndian.PutUint32(regs.data[start:end], uint32(linux.NF_CT_STATE_INVALID_BIT))
			return
		}
		regs.verdict = stack.NFVerdict{Code: VC(linux.NFT_BREAK)}
		return
	}

	isIPv4 := ctInfo.NetProto == header.IPv4ProtocolNumber
	isIPv6 := ctInfo.NetProto == header.IPv6ProtocolNumber

	// Set entire range to 0 first to handle padding.
	clear(regs.data[start:end])

	switch op.key {
	case linux.NFT_CT_STATE:
		state := ctStateToNFTState(ctInfo.State)
		binary.NativeEndian.PutUint32(regs.data[start:end], state)
	case linux.NFT_CT_DIRECTION:
		regs.data[start] = byte(ctInfo.Direction)
	case linux.NFT_CT_EXPIRATION:
		binary.NativeEndian.PutUint32(regs.data[start:end], uint32(ctInfo.Expiration.Milliseconds()))
	case linux.NFT_CT_ID:
		binary.NativeEndian.PutUint32(regs.data[start:end], ctInfo.PseudoID)
	case linux.NFT_CT_L3PROTOCOL:
		regs.data[start] = byte(netProtoToNFProto(ctInfo.NetProto))
	case linux.NFT_CT_PROTOCOL:
		regs.data[start] = byte(ctInfo.TransProto)
	case linux.NFT_CT_SRC:
		copy(regs.data[start:end], ctInfo.SrcAddr.AsSlice())
	case linux.NFT_CT_DST:
		copy(regs.data[start:end], ctInfo.DstAddr.AsSlice())
	case linux.NFT_CT_PROTO_SRC:
		binary.BigEndian.PutUint16(regs.data[start:start+2], ctInfo.SrcPort)
	case linux.NFT_CT_PROTO_DST:
		binary.BigEndian.PutUint16(regs.data[start:start+2], ctInfo.DstPort)
	case linux.NFT_CT_SRC_IP:
		if !isIPv4 {
			regs.verdict = stack.NFVerdict{Code: VC(linux.NFT_BREAK)}
			return
		}
		copy(regs.data[start:end], ctInfo.SrcAddr.AsSlice())
	case linux.NFT_CT_DST_IP:
		if !isIPv4 {
			regs.verdict = stack.NFVerdict{Code: VC(linux.NFT_BREAK)}
			return
		}
		copy(regs.data[start:end], ctInfo.DstAddr.AsSlice())
	case linux.NFT_CT_SRC_IP6:
		if !isIPv6 {
			regs.verdict = stack.NFVerdict{Code: VC(linux.NFT_BREAK)}
			return
		}
		copy(regs.data[start:end], ctInfo.SrcAddr.AsSlice())
	case linux.NFT_CT_DST_IP6:
		if !isIPv6 {
			regs.verdict = stack.NFVerdict{Code: VC(linux.NFT_BREAK)}
			return
		}
		copy(regs.data[start:end], ctInfo.DstAddr.AsSlice())
	default:
		regs.verdict = stack.NFVerdict{Code: VC(linux.NFT_BREAK)}
	}
}

// GetExprName implements operation's ExprName interface.
func (op *ctGet) GetExprName() string {
	return OpTypeCT.String()
}

// checkCompatibility implements operation's checkCompatibility interface.
func (op *ctGet) checkCompatibility(_ *opCompatCtx) *syserr.AnnotatedError {
	return nil
}

// deepCopy implements operation's deepCopy interface.
func (op *ctGet) deepCopy() operation {
	return &ctGet{
		key:     op.key,
		dregIdx: op.dregIdx,
		dir:     op.dir,
		len:     op.len,
	}
}

// Dump implements operation's Dump interface.
func (op *ctGet) Dump() ([]byte, *syserr.AnnotatedError) {
	m := &nlmsg.Message{}
	m.PutAttr(linux.NFTA_CT_KEY, nlmsg.PutU32(uint32(op.key)))
	m.PutAttr(linux.NFTA_CT_DREG, formatRegIdxForDump(op.dregIdx))
	if op.dir != linux.IP_CT_DIR_MAX {
		m.PutAttr(linux.NFTA_CT_DIRECTION, nlmsg.PutU8(uint8(op.dir)))
	}
	return m.Buffer(), nil
}

// Matches Linux net/netfilter/nft_ct.c:nft_ct_set_eval()
func (op *ctSet) evaluate(regs *registerSet, evalCtx opEvalCtx) {
	// TODO: b/531808852 - Implement ct set operation.
	log.Warningf("ctSet.evaluate is not implemented")
	regs.verdict = stack.NFVerdict{Code: VC(linux.NFT_BREAK)}
}

// GetExprName implements operation's ExprName interface.
func (op *ctSet) GetExprName() string {
	return OpTypeCT.String()
}

// Dump implements operation's Dump interface.
func (op *ctSet) Dump() ([]byte, *syserr.AnnotatedError) {
	m := &nlmsg.Message{}
	m.PutAttr(linux.NFTA_CT_KEY, nlmsg.PutU32(uint32(op.key)))
	m.PutAttr(linux.NFTA_CT_SREG, formatRegIdxForDump(op.sregIdx))
	if op.dir != linux.IP_CT_DIR_MAX {
		m.PutAttr(linux.NFTA_CT_DIRECTION, nlmsg.PutU8(uint8(op.dir)))
	}
	return m.Buffer(), nil
}

// checkCompatibility implements operation's checkCompatibility interface.
func (op *ctSet) checkCompatibility(_ *opCompatCtx) *syserr.AnnotatedError {
	return nil
}

// deepCopy implements operation's deepCopy interface.
func (op *ctSet) deepCopy() operation {
	return &ctSet{
		key:     op.key,
		sregIdx: op.sregIdx,
		dir:     op.dir,
		len:     op.len,
	}
}

// initCTSet initializes a ct set operation.
func initCTSet(tab *Table, sreg uint8, attrs map[uint16]nlmsg.BytesView) (*ctSet, *syserr.AnnotatedError) {
	return nil, syserr.NewAnnotatedError(syserr.ErrNotSupported, "ct set operation is not supported")
}

func ctKeyToLen(tab *Table, key uint32) (int, *syserr.AnnotatedError) {
	len := -1
	switch key {
	case linux.NFT_CT_DIRECTION, linux.NFT_CT_L3PROTOCOL, linux.NFT_CT_PROTOCOL:
		len = 1
	case linux.NFT_CT_STATE, linux.NFT_CT_STATUS, linux.NFT_CT_MARK, linux.NFT_CT_SECMARK, linux.NFT_CT_EXPIRATION:
		len = 4
	case linux.NFT_CT_LABELS:
		len = ctLabelsMaxSizeBytes
	case linux.NFT_CT_HELPER:
		len = ctHelperNameLen
	case linux.NFT_CT_SRC, linux.NFT_CT_DST:
		switch tab.afFilter.family {
		case stack.IP:
			len = 4
		case stack.IP6, stack.Inet:
			len = 16
		default:
			return len, syserr.NewAnnotatedError(
				syserr.ErrNotSupported,
				fmt.Sprintf("ct key %v is not supported for family %v", key, tab.afFilter.family),
			)
		}
	case linux.NFT_CT_SRC_IP, linux.NFT_CT_DST_IP:
		len = 4
	case linux.NFT_CT_SRC_IP6, linux.NFT_CT_DST_IP6:
		len = 16 // len = sizeof_field(struct nf_conntrack_tuple, src.u.all);
	case linux.NFT_CT_PROTO_SRC, linux.NFT_CT_PROTO_DST:
		len = 2
	case linux.NFT_CT_BYTES, linux.NFT_CT_PKTS, linux.NFT_CT_AVGPKT, linux.NFT_CT_ZONE:
		len = 8
	case linux.NFT_CT_ID:
		len = 4
	default:
		return len, syserr.NewAnnotatedError(
			syserr.ErrNotSupported,
			fmt.Sprintf("ct key %d is not supported", key),
		)
	}

	// round up to nearest multiple of 4.
	len = (len + 3) & ^3
	return len, nil
}

// initCTGet initializes a ct get operation.
// Ref: net/netfilter/nft_ct.c:nft_ct_get_init()
func initCTGet(tab *Table, dreg uint8, attrs map[uint16]nlmsg.BytesView) (*ctGet, *syserr.AnnotatedError) {
	key, ok := AttrNetToHost[uint32](linux.NFTA_CT_KEY, attrs)
	if !ok {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "failed to parse NFTA_CT_KEY attribute")
	}

	// TODO: b/531808852 - Support these keys.
	switch key {
	case linux.NFT_CT_STATUS, linux.NFT_CT_SECMARK, linux.NFT_CT_MARK, linux.NFT_CT_EVENTMASK,
		linux.NFT_CT_PKTS, linux.NFT_CT_BYTES, linux.NFT_CT_AVGPKT, linux.NFT_CT_ZONE:

		return nil, syserr.NewAnnotatedError(
			syserr.ErrNotSupported,
			fmt.Sprintf("ct key %d is not supported", key),
		)
	}

	dir, hasDir := AttrNetToHost[uint8](linux.NFTA_CT_DIRECTION, attrs)
	switch key {
	case linux.NFT_CT_DIRECTION, linux.NFT_CT_STATE, linux.NFT_CT_STATUS, linux.NFT_CT_MARK,
		linux.NFT_CT_SECMARK, linux.NFT_CT_EXPIRATION, linux.NFT_CT_HELPER, linux.NFT_CT_LABELS,
		linux.NFT_CT_ID:

		if hasDir {
			return nil, syserr.NewAnnotatedError(
				syserr.ErrInvalidArgument,
				fmt.Sprintf("direction is not allowed for key %d", key),
			)
		}

	case linux.NFT_CT_SRC, linux.NFT_CT_DST,
		linux.NFT_CT_SRC_IP, linux.NFT_CT_DST_IP, linux.NFT_CT_SRC_IP6, linux.NFT_CT_DST_IP6,
		linux.NFT_CT_PROTO_SRC, linux.NFT_CT_PROTO_DST:

		if !hasDir {
			return nil, syserr.NewAnnotatedError(
				syserr.ErrInvalidArgument,
				fmt.Sprintf("direction is required for key %d", key),
			)
		}
	}

	if hasDir {
		if dir != linux.IP_CT_DIR_ORIGINAL && dir != linux.IP_CT_DIR_REPLY {
			return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "invalid ct direction")
		}
	} else {
		dir = linux.IP_CT_DIR_MAX
	}

	len, err := ctKeyToLen(tab, key)
	if err != nil {
		return nil, err
	}

	dregIdx, err := regNumToIdx(dreg, len)
	if err != nil {
		return nil, err
	}

	return &ctGet{key: key, dregIdx: dregIdx, dir: dir, len: len}, nil
}

// ctAttrPolicy is the policy for parsing ct expression attributes.
// Matches Linux net/netfilter/nft_ct.c:nft_ct_policy
var ctAttrPolicy = []NlaPolicy{
	linux.NFTA_CT_DREG:      NlaPolicy{nlaType: linux.NLA_U32},
	linux.NFTA_CT_KEY:       NlaPolicy{nlaType: linux.NLA_BE32, validator: AttrMaxValidator[uint32](255)},
	linux.NFTA_CT_DIRECTION: NlaPolicy{nlaType: linux.NLA_U8},
	linux.NFTA_CT_SREG:      NlaPolicy{nlaType: linux.NLA_U32},
}

// initCT initializes a ct operation (either get or set).
// Ref: net/netfilter/nft_ct.c:nft_ct_init()
func initCT(tab *Table, exprInfo ExprInfo) (operation, *syserr.AnnotatedError) {
	attrs, ok := NfParseWithOpts(exprInfo.ExprData, &NfParseOpts{
		Policy: ctAttrPolicy,
	})
	if !ok {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "failed to parse ct expression data")
	}

	dreg, dregOK := AttrNetToHost[uint32](linux.NFTA_CT_DREG, attrs)
	sreg, sregOK := AttrNetToHost[uint32](linux.NFTA_CT_SREG, attrs)
	if dregOK && sregOK {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "ct expression cannot have both DREG and SREG")
	}

	if dregOK {
		return initCTGet(tab, uint8(dreg), attrs)
	}
	if sregOK {
		return initCTSet(tab, uint8(sreg), attrs)
	}
	return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "ct expression must have either DREG or SREG")
}
