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

// This file implements the conntrack XTables compatibility match operation.
// Ref: net/netfilter/xt_conntrack.c

package nftables

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/socket/netlink/nlmsg"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// ctMatchInfo stores params for conntrack match evaluation.
// Ref: net/netfilter/xt_conntrack.c:xt_conntrack_mtinfo2
type ctMatchInfo struct {
	// checkState indicates if state matching is enabled.
	checkState bool
	// invertStateMatch indicates if the state match result should be inverted.
	invertStateMatch bool
	// stateMask is the bitmask of states (NEW, ESTABLISHED, etc.) to match.
	stateMask uint16
	// checkDirection indicates whether reply/original direction matching is enabled.
	checkDirection bool
	// invertDirectionMatch indicates whether the direction match expects a
	// reply (true) or original (false) packet.
	invertDirectionMatch bool
}

// compatCTMatch implements the "conntrack" xtables match extension.
// It evaluates connection tracking state and
// direction against packet conntrack info.
type compatCTMatch struct {
	// revision is the XTables conntrack match extension revision (1, 2, or 3).
	revision uint32
	// infoData is the raw netlink attribute payload for serialization (NFTA_MATCH_INFO).
	infoData []byte
	// info holds the precomputed match flags and state masks.
	info ctMatchInfo
}

// match returns true if the packet matches the conntrack match.
// Ref: net/netfilter/xt_conntrack.c:conntrack_mt()
func (op *compatCTMatch) match(pkt *stack.PacketBuffer) bool {
	opInfo := &op.info
	var ctInfo stack.ConnTrackInfo
	ctOk := pkt.FillConnTrackInfo(stack.ConnTrackInfoOpts{
		FillState:   opInfo.checkState,
		UseReplyDir: pkt.IsReplyPacket(),
	}, &ctInfo)
	if !ctOk {
		// If ctInfo could not be found, then we can't match anything
		// other than the state (which evaluates as INVALID state).
		if !opInfo.checkState {
			return false
		}
		return ((opInfo.stateMask & linux.XT_CONNTRACK_STATE_INVALID) != 0) != opInfo.invertStateMatch
	}

	if opInfo.checkState {
		var statebit uint16
		switch ctInfo.State {
		case stack.ConnTrackStateNew:
			statebit = linux.XT_CONNTRACK_STATE_NEW
		case stack.ConnTrackStateEstablished, stack.ConnTrackStateEstablishedReply:
			statebit = linux.XT_CONNTRACK_STATE_ESTABLISHED
		default:
			// TODO: b/505405732 - Support
			// - XT_CONNTRACK_STATE_RELATED
			// - XT_CONNTRACK_STATE_UNTRACKED
			// - XT_CONNTRACK_STATE_SNAT/DNAT
			statebit = linux.XT_CONNTRACK_STATE_INVALID
		}
		matched := ((opInfo.stateMask & statebit) != 0) != opInfo.invertStateMatch
		if !matched {
			return false
		}
	}

	if opInfo.checkDirection {
		matched := (ctInfo.Direction == stack.ConnTrackDirectionOriginal) != opInfo.invertDirectionMatch
		if !matched {
			return false
		}
	}

	return true
}

// evaluate implements operation.evaluate.
func (op *compatCTMatch) evaluate(regs *registerSet, evalCtx opEvalCtx) {
	if op.match(evalCtx.pkt) {
		regs.verdict = Verdict{Code: VC(linux.NFT_CONTINUE)}
		return
	}
	regs.verdict = Verdict{Code: VC(linux.NFT_BREAK)}
}

// checkCompatibility implements operation.checkCompatibility.
func (op *compatCTMatch) checkCompatibility(cCtx *opCompatCtx) *syserr.AnnotatedError {
	return nil
}

// deepCopy implements operation.deepCopy.
func (op *compatCTMatch) deepCopy() operation {
	opCopy := *op
	opCopy.infoData = append([]byte(nil), op.infoData...)
	return &opCopy
}

// updateReferences implements operation.updateReferences.
func (op *compatCTMatch) updateReferences(table *Table, sourceTable *Table, sourceOp operation) {}

// destroy implements operation.destroy.
func (op *compatCTMatch) destroy() {}

// GetExprName implements operation.GetExprName.
func (op *compatCTMatch) GetExprName() string {
	return OpTypeMatch.String()
}

// Dump implements operation.Dump.
// Ref: net/netfilter/nft_compat.c:__nft_match_dump()
func (op *compatCTMatch) Dump() ([]byte, *syserr.AnnotatedError) {
	m := &nlmsg.Message{}
	m.PutAttrString(linux.NFTA_MATCH_NAME, MatchConntrack)
	m.PutAttr(linux.NFTA_MATCH_REV, nlmsg.PutU32(op.revision))
	if len(op.infoData) > 0 {
		m.PutAttr(linux.NFTA_MATCH_INFO, primitive.AsByteSlice(op.infoData))
	}
	return m.Buffer(), nil
}

func (info *ctMatchInfo) init(matchFlags, invertFlags, stateMask uint16) *syserr.AnnotatedError {
	// TODO: b/505405732 - Support additional conntrack match flags.
	supportedFlags := uint16(linux.XT_CONNTRACK_STATE | linux.XT_CONNTRACK_DIRECTION)
	if matchFlags&^supportedFlags != 0 {
		return syserr.NewAnnotatedError(syserr.ErrNotSupported, fmt.Sprintf("conntrack match flags 0x%x not supported", matchFlags))
	}

	info.checkState = matchFlags&linux.XT_CONNTRACK_STATE != 0
	info.invertStateMatch = invertFlags&linux.XT_CONNTRACK_STATE != 0
	info.stateMask = stateMask
	info.checkDirection = matchFlags&linux.XT_CONNTRACK_DIRECTION != 0
	info.invertDirectionMatch = invertFlags&linux.XT_CONNTRACK_DIRECTION != 0
	return nil
}

// unmarshalRev1 parses xt_conntrack_mtinfo and fills ctMatchInfo.
func (info *ctMatchInfo) unmarshalRev1(infoData []byte) *syserr.AnnotatedError {
	var mtinfo linux.XTConntrackMtinfo
	if len(infoData) < mtinfo.SizeBytes() {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "conntrack info data too small for revision 1")
	}
	mtinfo.UnmarshalBytes(infoData[:mtinfo.SizeBytes()])
	return info.init(mtinfo.MatchFlags, mtinfo.InvertFlags, uint16(mtinfo.StateMask))
}

// unmarshalRev2 fills xt_conntrack_mtinfo2 and populates ctMatchInfo.
func (info *ctMatchInfo) unmarshalRev2(infoData []byte) *syserr.AnnotatedError {
	var mtinfo linux.XTConntrackMtinfo2
	if len(infoData) < mtinfo.SizeBytes() {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "conntrack info data too small for revision 2")
	}
	mtinfo.UnmarshalBytes(infoData[:mtinfo.SizeBytes()])
	return info.init(mtinfo.MatchFlags, mtinfo.InvertFlags, mtinfo.StateMask)
}

// unmarshalRev3 parses xt_conntrack_mtinfo3 and fills ctMatchInfo.
func (info *ctMatchInfo) unmarshalRev3(infoData []byte) *syserr.AnnotatedError {
	var mtinfo linux.XTConntrackMtinfo3
	if len(infoData) < mtinfo.SizeBytes() {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "conntrack info data too small for revision 3")
	}
	mtinfo.UnmarshalBytes(infoData[:mtinfo.SizeBytes()])
	return info.init(mtinfo.MatchFlags, mtinfo.InvertFlags, mtinfo.StateMask)
}

const (
	conntrackRevision1   = 1
	conntrackRevision2   = 2
	conntrackRevision3   = 3
	conntrackMinRevision = conntrackRevision1
	conntrackMaxRevision = conntrackRevision3
)

// lookupConntrackRevision checks if a conntrack match revision is supported
// and returns the best revision.
func lookupConntrackRevision(rev uint32, _ stack.AddressFamily) (uint32, *syserr.AnnotatedError) {
	if rev < conntrackMinRevision || rev > conntrackMaxRevision {
		return 0, syserr.NewAnnotatedError(syserr.ErrNotSupported, fmt.Sprintf("conntrack revision %d not supported", rev))
	}
	return conntrackMaxRevision, nil
}

// parseConntrackMatch converts xtables attribute payload to ctMatchInfo Op.
// Ref: net/netfilter/xt_conntrack.c:conntrack_mt_check()
func parseConntrackMatch(rev uint32, infoData []byte) (*ctMatchInfo, *syserr.AnnotatedError) {
	info := &ctMatchInfo{}
	var err *syserr.AnnotatedError
	switch rev {
	case conntrackRevision1:
		err = info.unmarshalRev1(infoData)
	case conntrackRevision2:
		err = info.unmarshalRev2(infoData)
	case conntrackRevision3:
		err = info.unmarshalRev3(infoData)
	default:
		return nil, syserr.NewAnnotatedError(syserr.ErrNoSuchFile, fmt.Sprintf("conntrack revision %d not supported", rev))
	}
	if err != nil {
		return nil, err
	}
	return info, nil
}
