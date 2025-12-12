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
)

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

var metaAttrPolicy = []NlaPolicy{
	linux.NFTA_META_DREG: NlaPolicy{nlaType: linux.NLA_U32},
	linux.NFTA_META_KEY:  NlaPolicy{nlaType: linux.NLA_BE32, validator: AttrMaxValidator[uint32](255)},
	linux.NFTA_META_SREG: NlaPolicy{nlaType: linux.NLA_U32},
}

func initMeta(tab *Table, exprInfo ExprInfo) (operation, *syserr.AnnotatedError) {
	attrs, ok := NfParseWithPolicy(exprInfo.ExprData, metaAttrPolicy)
	if !ok {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: Failed to parse meta expression data")
	}
	if _, ok := attrs[linux.NFTA_META_SREG]; ok {
		if _, ok := attrs[linux.NFTA_META_DREG]; ok {
			return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: Only one of NFTA_PAYLOAD_SREG and NFTA_PAYLOAD_DREG should be set")
		}
		return initMetaSet(attrs)
	}
	if _, ok := attrs[linux.NFTA_META_DREG]; ok {
		return initMetaLoad(attrs)
	}
	return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: NFTA_PAYLOAD_SREG or NFTA_PAYLOAD_DREG attribute is not found")
}
