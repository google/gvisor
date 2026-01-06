// Copyright 2024 The gVisor Authors.
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
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/socket/netlink/nlmsg"
)

var nlaTypeToString = [...]string{
	linux.NLA_UNSPEC:       "NLA_UNSPEC",
	linux.NLA_U8:           "NLA_U8",
	linux.NLA_U16:          "NLA_U16",
	linux.NLA_U32:          "NLA_U32",
	linux.NLA_U64:          "NLA_U64",
	linux.NLA_STRING:       "NLA_STRING",
	linux.NLA_FLAG:         "NLA_FLAG",
	linux.NLA_MSECS:        "NLA_MSECS",
	linux.NLA_NESTED:       "NLA_NESTED",
	linux.NLA_NESTED_ARRAY: "NLA_NESTED_ARRAY",
	linux.NLA_NUL_STRING:   "NLA_NUL_STRING",
	linux.NLA_BINARY:       "NLA_BINARY",
	linux.NLA_S8:           "NLA_S8",
	linux.NLA_S16:          "NLA_S16",
	linux.NLA_S32:          "NLA_S32",
	linux.NLA_S64:          "NLA_S64",
	linux.NLA_BITFIELD32:   "NLA_BITFIELD32",
	linux.NLA_REJECT:       "NLA_REJECT",
	linux.NLA_BE16:         "NLA_BE16",
	linux.NLA_BE32:         "NLA_BE32",
}

// NlaPolicy represents the policy for a netlink attribute.
// Similar to struct nla_policy defined in include/net/netlink.h.
type NlaPolicy struct {
	nlaType   uint8
	validator NlaPolicyValidator
}

// NlaPolicyValidator is used to validate the data for a netlink attribute.
type NlaPolicyValidator func(data any) bool

func validateData(policy *NlaPolicy, data nlmsg.BytesView) bool {
	validator := policy.validator
	if validator == nil {
		// No validator is set, still check the data type
		// through the switch case below.
		validator = func(data any) bool { return true }
	}
	switch policy.nlaType {
	case linux.NLA_U8:
		if v, ok := data.Uint8(); ok {
			return validator(v)
		}
	case linux.NLA_S8:
		if v, ok := data.Int8(); ok {
			return validator(v)
		}
	case linux.NLA_U16:
		if v, ok := data.Uint16(); ok {
			return validator(v)
		}
	case linux.NLA_S16:
		if v, ok := data.Int16(); ok {
			return validator(v)
		}
	case linux.NLA_BE16:
		if v, ok := data.Uint16(); ok {
			return validator(nlmsg.NetToHostU16(v))
		}
	case linux.NLA_U32:
		if v, ok := data.Uint32(); ok {
			return validator(v)
		}
	case linux.NLA_S32:
		if v, ok := data.Int32(); ok {
			return validator(v)
		}
	case linux.NLA_BE32:
		if v, ok := data.Uint32(); ok {
			return validator(nlmsg.NetToHostU32(v))
		}
	case linux.NLA_U64:
		if v, ok := data.Uint64(); ok {
			return validator(v)
		}
	case linux.NLA_S64:
		if v, ok := data.Int64(); ok {
			return validator(v)
		}
	// return true for all other valid types.
	case linux.NLA_STRING,
		linux.NLA_NUL_STRING,
		linux.NLA_BINARY,
		linux.NLA_FLAG,
		linux.NLA_MSECS,
		linux.NLA_NESTED,
		linux.NLA_NESTED_ARRAY,
		linux.NLA_BITFIELD32,
		linux.NLA_REJECT:

		return true
	}
	return false
}

type integer interface {
	int | uint | int8 | uint8 | int16 | uint16 | int32 | uint32 | int64 | uint64
}

// AttrMaxValidator checks if the data is less than or equal to the maxValue.
func AttrMaxValidator[T integer](maxValue T) NlaPolicyValidator {
	return func(data any) bool {
		v, ok := data.(T)
		return ok && v <= maxValue
	}
}

// NfParseWithPolicy parses the data bytes, clearing the nested attribute bit if present.
// For nested attributes, Linux supports these attributes having the bit
// set or unset. It is cleared here for consistency. The policy map is used to validate the
// attributes with the given validation function, if present.
func NfParseWithPolicy(data nlmsg.AttrsView, policy []NlaPolicy) (map[uint16]nlmsg.BytesView, bool) {
	attrs, ok := data.Parse()
	if !ok {
		return nil, ok
	}
	policyLen := uint16(len(policy))
	newAttrs := make(map[uint16]nlmsg.BytesView)
	for attr, attrData := range attrs {
		unNestedAttr := attr & ^linux.NLA_F_NESTED
		policyExists := unNestedAttr < policyLen
		if policyExists {
			if ok := validateData(&policy[unNestedAttr], attrData); !ok {
				return nil, false
			}
		}
		newAttrs[unNestedAttr] = attrData
	}
	return newAttrs, true
}

// NfParse parses the data bytes with no validation.
func NfParse(data nlmsg.AttrsView) (map[uint16]nlmsg.BytesView, bool) {
	return NfParseWithPolicy(data, nil)
}

// HasAttr returns whether the given attribute key is present in the attribute map.
func HasAttr(attrName uint16, attrs map[uint16]nlmsg.BytesView) bool {
	_, ok := attrs[attrName]
	return ok
}

// AttrNetToHost returns the uint32 value of the attribute in host byte order.
func AttrNetToHost[T integer](attrName uint16, attrs map[uint16]nlmsg.BytesView) (T, bool) {
	attrData, ok := attrs[attrName]
	if !ok {
		return 0, false
	}
	var t T
	switch any(t).(type) {
	case uint8:
		v, ok := attrData.Uint8()
		if !ok {
			return 0, false
		}
		return T(v), true
	case uint16:
		v, ok := attrData.Uint16()
		if !ok {
			return 0, false
		}
		return T(nlmsg.NetToHostU16(v)), true
	case uint32:
		v, ok := attrData.Uint32()
		if !ok {
			return 0, false
		}
		return T(nlmsg.NetToHostU32(v)), true
	case uint64:
		v, ok := attrData.Uint64()
		if !ok {
			return 0, false
		}
		return T(nlmsg.NetToHostU64(v)), true
	default:
		return 0, false
	}
}
