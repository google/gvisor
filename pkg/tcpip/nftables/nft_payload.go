// Copyright 2025 The gVisor Authors.
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
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/syserr"
)

type payloadBase uint16

// payloadBaseStrings is a map of payloadBase to its string representation.
var payloadBaseStrings = []string{
	linux.NFT_PAYLOAD_LL_HEADER:        "Link Layer Header",
	linux.NFT_PAYLOAD_NETWORK_HEADER:   "Network Header",
	linux.NFT_PAYLOAD_TRANSPORT_HEADER: "Transport Header",
	linux.NFT_PAYLOAD_INNER_HEADER:     "Inner Header",
	linux.NFT_PAYLOAD_TUN_HEADER:       "Tunneling Header",
}

// String for payloadBase returns the string representation of the payload base.
func (base payloadBase) String() (string, *syserr.AnnotatedError) {
	if int(base) < len(payloadBaseStrings) {
		return payloadBaseStrings[base], nil
	}
	err := syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("invalid payload base: %d", int(base)))
	log.BugTraceback(err)
	return "", err
}

var payloadAttrStrings = []string{
	linux.NFTA_PAYLOAD_DREG:        "NFTA_PAYLOAD_DREG",
	linux.NFTA_PAYLOAD_BASE:        "NFTA_PAYLOAD_BASE",
	linux.NFTA_PAYLOAD_OFFSET:      "NFTA_PAYLOAD_OFFSET",
	linux.NFTA_PAYLOAD_LEN:         "NFTA_PAYLOAD_LEN",
	linux.NFTA_PAYLOAD_SREG:        "NFTA_PAYLOAD_SREG",
	linux.NFTA_PAYLOAD_CSUM_TYPE:   "NFTA_PAYLOAD_CSUM_TYPE",
	linux.NFTA_PAYLOAD_CSUM_OFFSET: "NFTA_PAYLOAD_CSUM_OFFSET",
	linux.NFTA_PAYLOAD_CSUM_FLAGS:  "NFTA_PAYLOAD_CSUM_FLAGS",
}

// payloadAttrToString returns the string representation of the payload attribute.
func payloadAttrToString(attr uint16) (string, *syserr.AnnotatedError) {
	if int(attr) < len(payloadAttrStrings) {
		return payloadAttrStrings[attr], nil
	}
	err := syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("unknown payload attribute: %d", attr))
	log.BugTraceback(err)
	return "", err
}

var payloadAttrPolicy = []NlaPolicy{
	linux.NFTA_PAYLOAD_SREG:        NlaPolicy{nlaType: linux.NLA_U32},
	linux.NFTA_PAYLOAD_DREG:        NlaPolicy{nlaType: linux.NLA_U32},
	linux.NFTA_PAYLOAD_BASE:        NlaPolicy{nlaType: linux.NLA_U32},
	linux.NFTA_PAYLOAD_OFFSET:      NlaPolicy{nlaType: linux.NLA_BE32, validator: AttrMaxValidator[uint32](255)},
	linux.NFTA_PAYLOAD_LEN:         NlaPolicy{nlaType: linux.NLA_BE32, validator: AttrMaxValidator[uint32](255)},
	linux.NFTA_PAYLOAD_CSUM_TYPE:   NlaPolicy{nlaType: linux.NLA_U32},
	linux.NFTA_PAYLOAD_CSUM_OFFSET: NlaPolicy{nlaType: linux.NLA_BE32, validator: AttrMaxValidator[uint32](255)},
	linux.NFTA_PAYLOAD_CSUM_FLAGS:  NlaPolicy{nlaType: linux.NLA_U32},
}

// validatePayloadBase ensures the payload base is valid.
func validatePayloadBase(base payloadBase) *syserr.AnnotatedError {
	switch base {
	// Supported payload bases.
	case linux.NFT_PAYLOAD_LL_HEADER, linux.NFT_PAYLOAD_NETWORK_HEADER, linux.NFT_PAYLOAD_TRANSPORT_HEADER:
		return nil
	// Unsupported payload bases.
	case linux.NFT_PAYLOAD_INNER_HEADER, linux.NFT_PAYLOAD_TUN_HEADER:
		baseStr, _ := base.String()
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("unsupported payload base: %v", baseStr))
	default:
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("unknown payload base: %d", int(base)))
	}
}

func initPayload(tab *Table, exprInfo ExprInfo) (operation, *syserr.AnnotatedError) {
	attrs, ok := NfParseWithPolicy(exprInfo.ExprData, payloadAttrPolicy)
	if !ok {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "failed to parse payload expression attributes")
	}
	if _, ok := attrs[linux.NFTA_PAYLOAD_SREG]; ok {
		if _, ok := attrs[linux.NFTA_PAYLOAD_DREG]; ok {
			return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "only one of NFTA_PAYLOAD_SREG and NFTA_PAYLOAD_DREG can be set")
		}
		return initPayloadSet(tab, attrs)
	}
	if _, ok := attrs[linux.NFTA_PAYLOAD_DREG]; ok {
		return initPayloadLoad(tab, attrs)
	}
	return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "NFTA_PAYLOAD_SREG or NFTA_PAYLOAD_DREG attribute is not found")
}
