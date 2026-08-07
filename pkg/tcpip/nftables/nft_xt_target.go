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

// This file implements XTables compatibility target dispatcher ("target" extensions)
// for nftables rules via nft-compat. It dispatches to specific target implementations
// like MASQUERADE, SNAT, and DNAT.
//
// Ref: net/netfilter/nft_compat.c

package nftables

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// lookupCompatTargetRevision validates if a target revision is supported
// and returns the best revision.
func lookupCompatTargetRevision(name string, rev uint32, family stack.AddressFamily) (uint32, *syserr.AnnotatedError) {
	switch name {
	case TargetMASQUERADE:
		return lookupMasqRevision(rev, family)
	case TargetSNAT, TargetDNAT:
		return lookupNATRevision(name, rev, family)
	default:
		return 0, syserr.NewAnnotatedError(syserr.ErrNoSuchFile, fmt.Sprintf("target extension %s not supported", name))
	}
}

// targetAttrPolicy defines the NLA policy for Target extensions.
// Ref: net/netfilter/nft_compat.c:nft_target_policy
var targetAttrPolicy = []NlaPolicy{
	linux.NFTA_TARGET_NAME: {nlaType: linux.NLA_NUL_STRING},
	linux.NFTA_TARGET_REV:  {nlaType: linux.NLA_BE32, validator: AttrMaxValidator[uint32](255)},
	linux.NFTA_TARGET_INFO: {nlaType: linux.NLA_BINARY},
}

// initTarget parses NFTA_TARGET_* netlink attributes and returns the op.
// Ref: net/netfilter/nft_compat.c:nft_target_init()
func initTarget(tab *Table, exprInfo ExprInfo) (operation, *syserr.AnnotatedError) {
	attrs, err := NfParseWithOpts(exprInfo.ExprData,
		&NfParseOpts{
			Policy: targetAttrPolicy,
		})
	if err != nil {
		return nil, err
	}

	nameAttr, ok := attrs[linux.NFTA_TARGET_NAME]
	if !ok {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "NFTA_TARGET_NAME attribute is not found")
	}
	name := nameAttr.String()

	rev, ok := AttrNetToHost[uint32](linux.NFTA_TARGET_REV, attrs)
	if !ok {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "NFTA_TARGET_REV attribute is not found")
	}

	infoAttr, ok := attrs[linux.NFTA_TARGET_INFO]
	if !ok {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "NFTA_TARGET_INFO attribute is not found")
	}
	infoData := []byte(infoAttr)

	switch name {
	case TargetMASQUERADE:
		info, err := parseMasqTarget(tab, rev, infoData)
		if err != nil {
			return nil, err
		}
		return &compatMASQTarget{revision: rev, infoData: infoData, info: *info}, nil
	case TargetSNAT, TargetDNAT:
		info, err := parseNATTarget(name, tab, rev, infoData)
		if err != nil {
			return nil, err
		}
		return &compatNATTarget{name: name, revision: rev, infoData: infoData, info: *info}, nil
	default:
		return nil, syserr.NewAnnotatedError(syserr.ErrNoSuchFile, fmt.Sprintf("target extension %s not supported", name))
	}
}
