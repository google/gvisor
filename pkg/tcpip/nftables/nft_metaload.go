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
	"encoding/binary"
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// metaLoad is an operation that loads specific meta data into a register.
// Note: meta operations are not supported for the verdict register.
// TODO(b/345684870): Support retrieving more meta fields for Meta Load.
type metaLoad struct {
	key  metaKey // Meta key specifying what data to retrieve.
	dreg uint8   // Number of the destination register.

	// Note: Similar to route, meta fields are stored AS IS. If the meta data is
	// a field stored by the kernel (i.e. length), it is stored in host endian. On
	// the contrary, if the meta data is data from the packet (i.e. protocol), it
	// is stored in big endian (network order).
	// The nft binary handles the necessary endian conversions from user input.
	// For example, if the user wants to check if meta len == 123 vs payload
	// data == 123, the nft binary passes host endian for the former and big
	// endian for the latter.
}

// metaKey is the key that determines the specific meta data to retrieve.
// Note: corresponds to enum nft_meta_keys from
// include/uapi/linux/netfilter/nf_tables.h and uses the same constants.
type metaKey int

// metaKeyStrings is a map of meta key to its string representation.
var metaKeyStrings = map[metaKey]string{
	linux.NFT_META_LEN:           "NFT_META_LEN",
	linux.NFT_META_PROTOCOL:      "NFT_META_PROTOCOL",
	linux.NFT_META_PRIORITY:      "NFT_META_PRIORITY",
	linux.NFT_META_MARK:          "NFT_META_MARK",
	linux.NFT_META_IIF:           "NFT_META_IIF",
	linux.NFT_META_OIF:           "NFT_META_OIF",
	linux.NFT_META_IIFNAME:       "NFT_META_IIFNAME",
	linux.NFT_META_OIFNAME:       "NFT_META_OIFNAME",
	linux.NFT_META_IIFTYPE:       "NFT_META_IIFTYPE",
	linux.NFT_META_OIFTYPE:       "NFT_META_OIFTYPE",
	linux.NFT_META_SKUID:         "NFT_META_SKUID",
	linux.NFT_META_SKGID:         "NFT_META_SKGID",
	linux.NFT_META_NFTRACE:       "NFT_META_NFTRACE",
	linux.NFT_META_RTCLASSID:     "NFT_META_RTCLASSID",
	linux.NFT_META_SECMARK:       "NFT_META_SECMARK",
	linux.NFT_META_NFPROTO:       "NFT_META_NFPROTO",
	linux.NFT_META_L4PROTO:       "NFT_META_L4PROTO",
	linux.NFT_META_BRI_IIFNAME:   "NFT_META_BRI_IIFNAME",
	linux.NFT_META_BRI_OIFNAME:   "NFT_META_BRI_OIFNAME",
	linux.NFT_META_PKTTYPE:       "NFT_META_PKTTYPE",
	linux.NFT_META_CPU:           "NFT_META_CPU",
	linux.NFT_META_IIFGROUP:      "NFT_META_IIFGROUP",
	linux.NFT_META_OIFGROUP:      "NFT_META_OIFGROUP",
	linux.NFT_META_CGROUP:        "NFT_META_CGROUP",
	linux.NFT_META_PRANDOM:       "NFT_META_PRANDOM",
	linux.NFT_META_SECPATH:       "NFT_META_SECPATH",
	linux.NFT_META_IIFKIND:       "NFT_META_IIFKIND",
	linux.NFT_META_OIFKIND:       "NFT_META_OIFKIND",
	linux.NFT_META_BRI_IIFPVID:   "NFT_META_BRI_IIFPVID",
	linux.NFT_META_BRI_IIFVPROTO: "NFT_META_BRI_IIFVPROTO",
	linux.NFT_META_TIME_NS:       "NFT_META_TIME_NS",
	linux.NFT_META_TIME_DAY:      "NFT_META_TIME_DAY",
	linux.NFT_META_TIME_HOUR:     "NFT_META_TIME_HOUR",
	linux.NFT_META_SDIF:          "NFT_META_SDIF",
	linux.NFT_META_SDIFNAME:      "NFT_META_SDIFNAME",
	linux.NFT_META_BRI_BROUTE:    "NFT_META_BRI_BROUTE",
}

// String for metaKey returns the string representation of the meta key. This
// supports strings for supported and unsupported meta keys.
func (key metaKey) String() string {
	if keyStr, ok := metaKeyStrings[key]; ok {
		return keyStr
	}
	panic(fmt.Sprintf("invalid meta key: %d", int(key)))
}

// metaDataLengths holds the length in bytes for each supported meta key.
var metaDataLengths = map[metaKey]int{
	linux.NFT_META_LEN:       4,
	linux.NFT_META_PROTOCOL:  2,
	linux.NFT_META_NFPROTO:   1,
	linux.NFT_META_L4PROTO:   1,
	linux.NFT_META_SKUID:     4,
	linux.NFT_META_SKGID:     4,
	linux.NFT_META_RTCLASSID: 4,
	linux.NFT_META_PKTTYPE:   1,
	linux.NFT_META_PRANDOM:   4,
	linux.NFT_META_TIME_NS:   8,
	linux.NFT_META_TIME_DAY:  1,
	linux.NFT_META_TIME_HOUR: 4,
}

// validateMetaKey ensures the meta key is valid.
func validateMetaKey(key metaKey) *syserr.AnnotatedError {
	switch key {
	case linux.NFT_META_LEN, linux.NFT_META_PROTOCOL, linux.NFT_META_NFPROTO,
		linux.NFT_META_L4PROTO, linux.NFT_META_SKUID, linux.NFT_META_SKGID,
		linux.NFT_META_RTCLASSID, linux.NFT_META_PKTTYPE, linux.NFT_META_PRANDOM,
		linux.NFT_META_TIME_NS, linux.NFT_META_TIME_DAY, linux.NFT_META_TIME_HOUR:

		return nil
	default:
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("meta key %v is not supported", key))
	}
}

// newMetaLoad creates a new metaLoad operation.
func newMetaLoad(key metaKey, dreg uint8) (*metaLoad, *syserr.AnnotatedError) {
	if isVerdictRegister(dreg) {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("meta load operation does not support verdict register as destination register"))
	}
	if err := validateMetaKey(key); err != nil {
		return nil, err
	}
	if metaDataLengths[key] > 4 && !is16ByteRegister(dreg) {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("meta load operation cannot use 4-byte register as destination for key %v", key))
	}

	return &metaLoad{key: key, dreg: dreg}, nil
}

// evaluate for MetaLoad loads specific meta data into the destination register.
func (op metaLoad) evaluate(regs *registerSet, pkt *stack.PacketBuffer, rule *Rule) {
	var target []byte
	switch op.key {

	// Packet Length, in bytes (32-bit, host order).
	case linux.NFT_META_LEN:
		target = binary.NativeEndian.AppendUint32(nil, uint32(pkt.Size()))

	// Network EtherType Protocol (16-bit, network order).
	case linux.NFT_META_PROTOCOL:
		// Only valid if network header is present.
		if pkt.NetworkHeader().View() == nil {
			break
		}
		target = binary.BigEndian.AppendUint16(nil, uint16(pkt.NetworkProtocolNumber))

	// Netfilter (Family) Protocol (8-bit, single byte).
	case linux.NFT_META_NFPROTO:
		family := rule.chain.GetAddressFamily()
		target = []byte{AfProtocol(family)}

	// L4 Transport Layer Protocol (8-bit, single byte).
	case linux.NFT_META_L4PROTO:
		// Only valid if non-zero.
		if pkt.TransportProtocolNumber == 0 {
			break
		}
		target = []byte{uint8(pkt.TransportProtocolNumber)}

	// Originating Socket UID (32-bit, host order).
	case linux.NFT_META_SKUID:
		// Only valid if Owner is set (only set for locally generated packets).
		if pkt.Owner == nil {
			break
		}
		target = binary.NativeEndian.AppendUint32(nil, pkt.Owner.KUID())

	// Originating Socket GID (32-bit, host order).
	case linux.NFT_META_SKGID:
		// Only valid if Owner is set (only set for locally generated packets).
		if pkt.Owner == nil {
			break
		}
		target = binary.NativeEndian.AppendUint32(nil, pkt.Owner.KGID())

	// Route Traffic Class ID, same as Route equivalent (32-bit, host order).
	// Currently only implemented for IPv6, but should be for IPv4 as well.
	case linux.NFT_META_RTCLASSID:
		if pkt.NetworkProtocolNumber != header.IPv6ProtocolNumber {
			break
		}
		if pkt.NetworkHeader().View() != nil {
			tcid, _ := pkt.Network().TOS()
			target = binary.NativeEndian.AppendUint32(nil, uint32(tcid))
		}

	// Packet Type (8-bit, single byte).
	case linux.NFT_META_PKTTYPE:
		target = []byte{uint8(pkt.PktType)}

	// Generated Pseudo-Random Number (32-bit, network order).
	case linux.NFT_META_PRANDOM:
		rng := rule.chain.table.afFilter.nftState.rng
		target = binary.BigEndian.AppendUint32(nil, uint32(rng.Uint32()))

	// Unix Time in Nanoseconds (64-bit, host order).
	case linux.NFT_META_TIME_NS:
		clock := rule.chain.table.afFilter.nftState.clock
		target = binary.NativeEndian.AppendUint64(nil, uint64(clock.Now().UnixNano()))

	// Day of Week (0 = Sunday, 6 = Saturday) (8-bit, single byte).
	case linux.NFT_META_TIME_DAY:
		clock := rule.chain.table.afFilter.nftState.clock
		target = []byte{uint8(clock.Now().Weekday())}

	// Hour of Day, in seconds (seconds since start of day) (32-bit, host order).
	case linux.NFT_META_TIME_HOUR:
		clock := rule.chain.table.afFilter.nftState.clock
		now := clock.Now()
		secs := now.Hour()*3600 + now.Minute()*60 + now.Second()
		target = binary.NativeEndian.AppendUint32(nil, uint32(secs))
	}

	// Breaks if could not retrieve meta data.
	if target == nil {
		regs.verdict = stack.NFVerdict{Code: VC(linux.NFT_BREAK)}
		return
	}

	// Gets the destination register.
	dst := getRegisterBuffer(regs, op.dreg)
	// Zeroes out excess bytes of the destination register.
	// This is done since comparison can be done in multiples of 4 bytes.
	blen := metaDataLengths[op.key]
	if rem := blen % 4; rem != 0 {
		clear(dst[blen : blen+4-rem])
	}
	// Copies target data into the destination register.
	copy(dst, target)
}
