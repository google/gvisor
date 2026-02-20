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
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// route is an operation that loads specific route data into a register.
// Note: route operations are not supported for the verdict register.
type route struct {
	key  routeKey // Route key specifying what data to retrieve.
	dreg uint8    // Number of the destination register.

	// Route information is stored AS IS. If the data is a field stored by the
	// kernel, it is stored in host endian. If the data is from the packet, it
	// is stored in big endian (network order).
	// The nft binary handles the necessary endian conversions from user input.
	// For example, if the user wants to check if some kernel data == 123 vs
	// payload data == 123, the nft binary passes host endian register data for
	// the former and big endian register data for the latter.
}

// routeKey is the key that determines the specific route data to retrieve.
// Note: corresponds to enum nft_rt_keys from
// include/uapi/linux/netfilter/nf_tables.h and uses the same constants.
type routeKey int

// routeKeyStrings is a map of route key to its string representation.
var routeKeyStrings = map[routeKey]string{
	linux.NFT_RT_CLASSID:  "Traffic Class ID",
	linux.NFT_RT_NEXTHOP4: "Next Hop IPv4",
	linux.NFT_RT_NEXTHOP6: "Next Hop IPv6",
	linux.NFT_RT_TCPMSS:   "TCP Maximum Segment Size (TCPMSS)",
	linux.NFT_RT_XFRM:     "IPsec Transformation",
}

// String for routeKey returns the string representation of the route key.
func (key routeKey) String() string {
	if keyStr, ok := routeKeyStrings[key]; ok {
		return keyStr
	}
	panic(fmt.Sprintf("invalid route key: %d", int(key)))
}

// validateRouteKey ensures the route key is valid.
func validateRouteKey(key routeKey) *syserr.AnnotatedError {
	switch key {
	// Supported route keys.
	case linux.NFT_RT_NEXTHOP4, linux.NFT_RT_NEXTHOP6, linux.NFT_RT_TCPMSS:
		return nil
	// Unsupported route keys.
	case linux.NFT_RT_CLASSID:
		// Note: We can trivially support Traffic Class ID for IPv6, but we need to
		// do more work to support it for IPv4. For safety, we mark it as
		// unsupported since we don't know what packet type we're working with until
		// the time of evaluation. In the worst case, we don't want the user to
		// initialize a route with this key and then have it silently break and
		// yield a difficult-to-debug error.
		return syserr.NewAnnotatedError(syserr.ErrNotSupported, "traffic class id not supported")
	case linux.NFT_RT_XFRM:
		return syserr.NewAnnotatedError(syserr.ErrNotSupported, "xfrm transformation not supported")
	default:
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("unknown route key: %d", int(key)))
	}
}

// newRoute creates a new route operation.
func newRoute(key routeKey, dreg uint8) (*route, *syserr.AnnotatedError) {
	if isVerdictRegister(dreg) {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "route operation does not support verdict register as destination register")
	}
	if err := validateRouteKey(key); err != nil {
		return nil, err
	}

	return &route{key: key, dreg: dreg}, nil
}

// evaluate for Route loads specific routing data into the destination register.
func (op route) evaluate(regs *registerSet, pkt *stack.PacketBuffer, rule *Rule) {
	// Gets the target data to be stored in the destination register.
	var target []byte
	switch op.key {

	// Retrieves next hop IPv4 address (restricted to IPv4).
	// Stores data in big endian network order.
	case linux.NFT_RT_NEXTHOP4:
		if pkt.NetworkProtocolNumber != header.IPv4ProtocolNumber {
			break
		}
		target = pkt.EgressRoute.NextHop.AsSlice()

	// Retrieves next hop IPv6 address (restricted to IPv6).
	// Stores data in big endian network order.
	case linux.NFT_RT_NEXTHOP6:
		if pkt.NetworkProtocolNumber != header.IPv6ProtocolNumber {
			break
		}
		target = pkt.EgressRoute.NextHop.AsSlice()

	// Retrieves the TCP Maximum Segment Size (TCPMSS).
	// Stores data in host endian.
	case linux.NFT_RT_TCPMSS:
		tcpmss := pkt.GSOOptions.MSS
		target = binary.NativeEndian.AppendUint16(nil, tcpmss)
	}

	// Breaks if could not retrieve target data.
	if target == nil {
		regs.verdict = stack.NFVerdict{Code: VC(linux.NFT_BREAK)}
		return
	}

	// Stores the target data in the destination register.
	data := newBytesData(target)
	data.storeData(regs, op.dreg)
}

func (op route) GetExprName() string {
	return "route"
}

// TODO: b/452648112 - Implement dump for last operation.
func (op route) Dump() ([]byte, *syserr.AnnotatedError) {
	log.Warningf("Nftables: Dumping route operation is not implemented")
	return nil, nil
}
