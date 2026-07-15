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

package nftables

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/socket/netlink/nlmsg"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// lookup represents a lookup operation.
// Matches Linux net/netfilter/nft_lookup.c.
type lookupOp struct {
	// sregIdx represents the index of the key in the register set.
	sregIdx int
	// set represents the nftSet to lookup key in.
	set *nftSet
	// invert represents whether to invert the result of the lookup.
	invert bool
	// fillData represents whether to fill value from the set element
	// into the register set.
	fillData bool
	// dregIdx represents the index of the data in the register set.
	dregIdx int
}

// evaluate implements operation.evaluate.
// Ref: net/netfilter/nft_lookup.c:nft_lookup_eval()
func (op *lookupOp) evaluate(regs *registerSet, evalCtx opEvalCtx) {
	valIdx := op.set.backend.Evaluate(regs, op.sregIdx)
	found := valIdx != -1
	if op.invert {
		found = !found
	}

	var elem *nftSetElem
	if found && valIdx != -1 {
		elem = &op.set.elements[valIdx]
	} else if !found && op.set.catchAllElem != nil {
		found = true
		elem = op.set.catchAllElem
	}

	if !found {
		// Break from rule if not found.
		regs.verdict = stack.NFVerdict{Code: VC(linux.NFT_BREAK)}
		return
	}

	if elem == nil {
		return
	}

	if op.fillData {
		// length of data was already verified in initLookup.
		d := &elem.data
		if d.isVerdict {
			regs.verdict = d.verdict
		} else {
			copy(regs.data[op.dregIdx:], d.data[:])
		}
	}

	// Evaluate expressions for set elements.
	for _, eOp := range elem.ops {
		eOp.evaluate(regs, evalCtx)
	}
}

func (op *lookupOp) GetExprName() string {
	return OpTypeLookup.String()
}

// Dump implements operation.Dump.
// Ref: net/netfilter/nft_lookup.c:nft_lookup_dump()
func (op *lookupOp) Dump() ([]byte, *syserr.AnnotatedError) {
	m := &nlmsg.Message{}
	m.PutAttrString(linux.NFTA_LOOKUP_SET, op.set.name)
	m.PutAttr(linux.NFTA_LOOKUP_SREG, nlmsg.PutU32(formatRegIdxForDump(op.sregIdx)))
	if op.fillData {
		m.PutAttr(linux.NFTA_LOOKUP_DREG, nlmsg.PutU32(formatRegIdxForDump(op.dregIdx)))
	}
	var flags uint32
	if op.invert {
		flags |= linux.NFT_LOOKUP_F_INV
	}
	m.PutAttr(linux.NFTA_LOOKUP_FLAGS, nlmsg.PutU32(flags))
	return m.Buffer(), nil
}

func (op *lookupOp) deepCopy() operation {
	opCopy := &lookupOp{}
	opCopy.set = op.set
	opCopy.sregIdx = op.sregIdx
	opCopy.fillData = op.fillData
	opCopy.dregIdx = op.dregIdx
	opCopy.invert = op.invert
	return opCopy
}

// checkCompatibility implements operation.checkCompatibility.
func (op *lookupOp) checkCompatibility(cCtx *opCompatCtx) *syserr.AnnotatedError {
	return nil
}

// lookupPolicy represents the policy for parsing the lookup attributes.
// Ref: net/netfilter/nft_lookup.c:nft_lookup_policy
var lookupPolicy = []NlaPolicy{
	linux.NFTA_LOOKUP_SET:    {nlaType: linux.NLA_STRING, validator: AttrMaxLenValidator(linux.NFT_SET_MAXNAMELEN - 1)},
	linux.NFTA_LOOKUP_SET_ID: {nlaType: linux.NLA_U32},
	linux.NFTA_LOOKUP_SREG:   {nlaType: linux.NLA_U32},
	linux.NFTA_LOOKUP_DREG:   {nlaType: linux.NLA_U32},
	linux.NFTA_LOOKUP_FLAGS:  {nlaType: linux.NLA_BE32, validator: AttrMaskValidator(linux.NFT_LOOKUP_F_INV)},
}

// initLookup initializes a lookup operation.
// Ref: net/netfilter/nft_lookup.c:nft_lookup_init()
func initLookup(tab *Table, exprInfo ExprInfo) (*lookupOp, *syserr.AnnotatedError) {
	lookupAttrs, ok := NfParseWithOpts(exprInfo.ExprData, &NfParseOpts{
		Policy: lookupPolicy,
	})
	if !ok {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "failed to parse lookup expression data")
	}

	setAttr, ok := lookupAttrs[linux.NFTA_LOOKUP_SET]
	if !ok {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "NFTA_LOOKUP_SET attribute not found")
	}

	sreg, ok := AttrNetToHost[uint32](linux.NFTA_LOOKUP_SREG, lookupAttrs)
	if !ok {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "NFTA_LOOKUP_SREG attribute not found")
	}

	setName := setAttr.String()
	set, ok := tab.sets[setName]
	if !ok {
		setID, ok := AttrNetToHost[uint32](linux.NFTA_LOOKUP_SET_ID, lookupAttrs)
		if !ok {
			return nil, syserr.NewAnnotatedError(syserr.ErrNoFileOrDir, "NFTA_LOOKUP_SET_ID attribute not found")
		}
		set, ok = tab.setHandles[uint64(setID)]
		if !ok {
			return nil, syserr.NewAnnotatedError(syserr.ErrNoFileOrDir, fmt.Sprintf("set with id %d not found", setID))
		}
	}

	sregIdx, err := regNumToIdx(uint8(sreg), int(set.keyLen))
	if err != nil {
		return nil, err
	}

	invert := false
	if flagsAttr, ok := AttrNetToHost[uint32](linux.NFTA_LOOKUP_FLAGS, lookupAttrs); ok {
		if flagsAttr & ^uint32(linux.NFT_LOOKUP_F_INV) != 0 {
			return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "invalid lookup flags")
		}
		if flagsAttr&linux.NFT_LOOKUP_F_INV != 0 {
			if (set.flags & linux.NFT_SET_MAP) != 0 {
				return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "invert flag cannot be set with map set")
			}
			invert = true
		}
	}

	dreg, dregExists := AttrNetToHost[uint32](linux.NFTA_LOOKUP_DREG, lookupAttrs)
	if (set.flags&linux.NFT_SET_MAP) != 0 && !dregExists {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "map set requires DREG")
	}
	dregIdx := -1
	if dregExists {
		if invert {
			return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "invert flag cannot be set with DREG")
		}
		if set.flags&linux.NFT_SET_MAP == 0 {
			return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "DREG cannot be set with non-map set")
		}
		if dreg != linux.NFT_REG_VERDICT {
			dregIdx, err = regNumToIdx(uint8(dreg), int(set.dataLen))
			if err != nil {
				return nil, err
			}
		}
	}

	op := &lookupOp{
		set:      set,
		sregIdx:  sregIdx,
		fillData: dregExists,
		dregIdx:  dregIdx,
		invert:   invert,
	}

	// As we use a copy of the nftables structure,
	// and adding a new op is sequential, we don't need to have a mutex.
	set.bindings = append(set.bindings, op)
	return op, nil
}
