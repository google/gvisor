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
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// metaSet is an operation that sets specific meta data into to the value in a
// register.
// Note: meta operations are not supported for the verdict register.
// TODO(b/345684870): Support setting more meta fields for Meta Set.
type metaSet struct {
	key  metaKey // Meta key specifying what data to set.
	sreg uint8   // Number of the source register.
}

// checkMetaKeySetCompatible checks that the meta key is valid for meta set.
func checkMetaKeySetCompatible(key metaKey) *syserr.AnnotatedError {
	switch key {
	// Supported meta keys.
	case linux.NFT_META_PKTTYPE:
		return nil
	// Should be supported but not yet implemented.
	case linux.NFT_META_MARK, linux.NFT_META_PRIORITY,
		linux.NFT_META_NFTRACE, linux.NFT_META_SECMARK:

		return syserr.NewAnnotatedError(syserr.ErrNotSupported, fmt.Sprintf("meta key %v is not supported", key))
	// All other keys cannot be used with meta set (strictly for loading).
	default:
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("meta key %v is not supported for meta set", key))
	}
}

// newMetaSet creates a new metaSet operation.
func newMetaSet(key metaKey, sreg uint8) (*metaSet, *syserr.AnnotatedError) {
	if isVerdictRegister(sreg) {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("meta set operation does not support verdict register as source register"))
	}
	if err := validateMetaKey(key); err != nil {
		return nil, err
	}
	if err := checkMetaKeySetCompatible(key); err != nil {
		return nil, err
	}
	if metaDataLengths[key] > 4 && !is16ByteRegister(sreg) {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("meta load operation cannot use 4-byte register as destination for key %s", key))
	}

	return &metaSet{key: key, sreg: sreg}, nil
}

// evaluate for metaSet sets specific meta data to the value in the source
// register.
func (op metaSet) evaluate(regs *registerSet, pkt *stack.PacketBuffer, rule *Rule) {
	// Gets the data from the source register.
	src := getRegisterBuffer(regs, op.sreg)[:metaDataLengths[op.key]]

	// Sets the meta data of the appropriate field.
	switch op.key {
	// Only Packet Type is supported for now.
	case linux.NFT_META_PKTTYPE:
		pkt.PktType = tcpip.PacketType(src[0])
		return
	}

	// Breaks if could not set the meta data.
	regs.verdict = stack.NFVerdict{Code: VC(linux.NFT_BREAK)}
	return
}
