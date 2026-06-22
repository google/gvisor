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
	"math"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/socket/netlink/nlmsg"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// isSame checks if the set is the same as the given set description.
// Ref: net/netfilter/nf_tables_api.c:nft_set_is_same
func (s *nftSet) isSame(other *nftSet) bool {
	if s.keyType != other.keyType ||
		s.dataType != other.dataType ||
		s.flags != other.flags ||
		s.keyLen != other.keyLen ||
		s.dataLen != other.dataLen || s.fieldCount != other.fieldCount ||
		s.timeout != other.timeout ||
		s.gcInterval != other.gcInterval ||
		s.policy != other.policy ||
		len(s.exprInfos) != len(other.exprInfos) {
		return false
	}

	for i := uint8(0); i < s.fieldCount; i++ {
		if s.fieldLen[i] != other.fieldLen[i] {
			return false
		}
	}

	// TODO: b/505409691 - Compare exprs.
	return true
}

// AddSetToTable adds a new set to the corresponding table, returning an error if
// the table doesn't exist or a set by the same name already exists.
func (nf *NFTables) addSetToTable(tab *Table, set *nftSet) *syserr.AnnotatedError {
	handle := tab.getNewHandle()
	set.handle = handle
	tab.sets[set.name] = set
	tab.setHandles[handle] = set
	return nil
}

// validateSetFlags validates the set flags.
// Ref: net/netfilter/nf_tables_api.c:nf_tables_newset
func validateSetFlags(flags uint16) *syserr.AnnotatedError {
	if flags&^(linux.NFT_SET_ANONYMOUS|linux.NFT_SET_CONSTANT|
		linux.NFT_SET_INTERVAL|linux.NFT_SET_TIMEOUT|
		linux.NFT_SET_MAP|linux.NFT_SET_EVAL|
		linux.NFT_SET_OBJECT|linux.NFT_SET_CONCAT|linux.NFT_SET_EXPR) != 0 {
		return syserr.NewAnnotatedError(syserr.ErrNotSupported, "Unsupported set flags")
	}
	if (flags & (linux.NFT_SET_MAP | linux.NFT_SET_OBJECT)) ==
		(linux.NFT_SET_MAP | linux.NFT_SET_OBJECT) {
		return syserr.NewAnnotatedError(syserr.ErrNotSupported, "Only one of NFT_SET_MAP or NFT_SET_OBJECT is supported")
	}
	if (flags & (linux.NFT_SET_EVAL | linux.NFT_SET_OBJECT)) ==
		(linux.NFT_SET_EVAL | linux.NFT_SET_OBJECT) {
		return syserr.NewAnnotatedError(syserr.ErrNotSupported, "Only one of NFT_SET_EVAL or NFT_SET_OBJECT is supported")
	}
	if (flags & (linux.NFT_SET_ANONYMOUS | linux.NFT_SET_TIMEOUT | linux.NFT_SET_EVAL)) ==
		(linux.NFT_SET_ANONYMOUS | linux.NFT_SET_TIMEOUT) {
		return syserr.NewAnnotatedError(syserr.ErrNotSupported, "Only one of NFT_SET_ANONYMOUS or NFT_SET_TIMEOUT is supported")
	}
	if (flags & (linux.NFT_SET_CONSTANT | linux.NFT_SET_TIMEOUT)) ==
		(linux.NFT_SET_CONSTANT | linux.NFT_SET_TIMEOUT) {
		return syserr.NewAnnotatedError(syserr.ErrNotSupported, "Only one of NFT_SET_CONSTANT or NFT_SET_TIMEOUT is supported")
	}
	return nil
}

// parseSetDataAttr parses the set data type and length attributes.
// Ref: net/netfilter/nf_tables_api.c:nf_tables_newset
func parseSetDataAttr(attrs map[uint16]nlmsg.BytesView, setFlags uint16) (dataType uint32, dataLen uint32, err *syserr.AnnotatedError) {
	dataType, ok := AttrNetToHost[uint32](linux.NFTA_SET_DATA_TYPE, attrs)
	if !ok {
		if setFlags&linux.NFT_SET_MAP != 0 {
			return 0, 0, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Set data type attribute is missing")
		}
		// If the set is not a map, then the data type attribute is not required.
		return 0, 0, nil
	}
	if setFlags&linux.NFT_SET_MAP == 0 {
		return 0, 0, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Set data type attribute should not be present for non-map set")
	}
	if (dataType&linux.NFT_DATA_RESERVED_MASK) == linux.NFT_DATA_RESERVED_MASK &&
		dataType != linux.NFT_DATA_VERDICT {
		return 0, 0, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Unsupported set data type")
	}
	if dataType == linux.NFT_DATA_VERDICT {
		return dataType, 16, nil
	}
	dataLen, ok = AttrNetToHost[uint32](linux.NFTA_SET_DATA_LEN, attrs)
	if !ok {
		return 0, 0, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Set data length attribute is missing")
	}
	if dataLen == 0 || dataLen > linux.NFT_DATA_VALUE_MAXLEN {
		return 0, 0, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Invalid set data length")
	}
	return dataType, dataLen, nil
}

// parseSetObjectAttr parses the set object type attribute.
// Ref: net/netfilter/nf_tables_api.c:nf_tables_newset
func parseSetObjectAttr(attrs map[uint16]nlmsg.BytesView, setFlags uint16) (objType uint32, err *syserr.AnnotatedError) {
	objType, ok := AttrNetToHost[uint32](linux.NFTA_SET_OBJ_TYPE, attrs)
	if ok && (setFlags&linux.NFT_SET_OBJECT == 0) {
		return 0, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Set object flag is not set but object type attribute is present")
	}
	if !ok && (setFlags&linux.NFT_SET_OBJECT != 0) {
		return 0, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Set object flag is set but object type attribute is missing")
	}
	if !ok {
		// The object type attribute is not required if the set is not an object set.
		return linux.NFT_OBJECT_UNSPEC, nil
	}
	if objType == linux.NFT_OBJECT_UNSPEC || objType > linux.NFT_OBJECT_MAX {
		return 0, syserr.NewAnnotatedError(syserr.ErrNotSupported, "Invalid set object type")
	}
	return objType, nil
}

// parseSetTimeoutAttr parses the set timeout attribute.
// Ref: net/netfilter/nf_tables_api.c:nf_tables_newset
func parseSetTimeoutAttr(attrs map[uint16]nlmsg.BytesView, setFlags uint16) (timeMiliSec uint64, err *syserr.AnnotatedError) {
	timeMS, ok := AttrNetToHost[uint64](linux.NFTA_SET_TIMEOUT, attrs)
	if ok && (setFlags&linux.NFT_SET_TIMEOUT == 0) {
		return 0, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Set timeout flag is not set but timeout attribute is present")
	}
	if !ok {
		// The timeout attribute is not a required attribute.
		return 0, nil
	}
	if setFlags&linux.NFT_SET_ANONYMOUS != 0 {
		return 0, syserr.NewAnnotatedError(syserr.ErrNotSupported, "Set timeout flag is not supported for anonymous sets")
	}
	return timeMS, nil
}

// parseSetGCIntervalAttr parses the set gc interval attribute.
// Ref: net/netfilter/nf_tables_api.c:nf_tables_newset
// TODO: b/505409691 - Add support for timeout and gc.
func parseSetGCIntervalAttr(attrs map[uint16]nlmsg.BytesView, setFlags uint16) (gcIntMiliSec uint32, err *syserr.AnnotatedError) {
	gc, ok := AttrNetToHost[uint32](linux.NFTA_SET_GC_INTERVAL, attrs)
	if !ok {
		// The gc interval attribute is not a required attribute.
		return 0, nil
	}
	if setFlags&linux.NFT_SET_TIMEOUT == 0 {
		return 0, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Set gc flag is not set but gc attribute is present")
	}
	if setFlags&linux.NFT_SET_ANONYMOUS != 0 {
		return 0, syserr.NewAnnotatedError(syserr.ErrNotSupported, "Set gc flag is not supported for anonymous sets")
	}
	return gc, nil
}

// parseSetPolicyAttr parses the set policy attribute.
// Ref: net/netfilter/nf_tables_api.c:nf_tables_newset
// TODO: b/505409691 - Add support for policy.
func parseSetPolicyAttr(attrs map[uint16]nlmsg.BytesView, setFlags uint16) (policy uint32, err *syserr.AnnotatedError) {
	policy, ok := AttrNetToHost[uint32](linux.NFTA_SET_POLICY, attrs)
	if !ok {
		// The policy attribute is not a required attribute;
		// default to performance optimized.
		return linux.NFT_SET_POL_PERFORMANCE, nil
	}
	if policy != linux.NFT_SET_POL_PERFORMANCE && policy != linux.NFT_SET_POL_MEMORY {
		return 0, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Invalid set policy")
	}
	return policy, nil
}

// setConcatPolicy is the policy for parsing the set description concat attributes.
// Ref: net/netfilter/nf_tables_api.c:nft_concat_policy
var setConcatPolicy = []NlaPolicy{
	linux.NFTA_SET_FIELD_LEN: {nlaType: linux.NLA_U32},
}

// parseSetConcatAttr parses the set description concat attributes.
// Ref: net/netfilter/nf_tables_api.c:nft_set_desc_concat_parse
func parseSetConcatAttr(descConcatAttrs nlmsg.BytesView, keyLen uint32) (concat []uint8, err *syserr.AnnotatedError) {
	roundUpToNearestMultipleOfFour := func(num uint32) uint32 {
		return (num + (3)) & ^uint32(3)
	}

	concatAttrsList := nlmsg.AttrsView(descConcatAttrs)
	var concatList [linux.NFT_REG32_COUNT]uint8
	i := 0
	totalLen := uint32(0)
	for !concatAttrsList.Empty() {
		if i >= len(concatList) {
			return nil, syserr.NewAnnotatedError(syserr.ErrFileTooBig, "Too many set description concat elements")
		}
		hdr, value, rest, ok := concatAttrsList.ParseFirst()
		if !ok {
			return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Failed to parse set description concat element")
		}
		concatAttrsList = rest
		if hdr.Type != linux.NFTA_LIST_ELEM {
			return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Set description concat element is not of type NFTA_LIST_ELEM")
		}
		concatElem, ok := NfParseWithOpts(nlmsg.AttrsView(value), &NfParseOpts{
			Policy: setConcatPolicy,
		})
		if !ok {
			return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Failed to parse set description concat element attributes")
		}
		fieldLen, ok := AttrNetToHost[uint32](linux.NFTA_SET_FIELD_LEN, concatElem)
		if !ok {
			return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Failed to parse set description field length")
		}
		if fieldLen == 0 || fieldLen > math.MaxUint8 {
			return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Invalid set field length")
		}

		concatList[i] = uint8(fieldLen)
		i++
		totalLen += roundUpToNearestMultipleOfFour(fieldLen)
	}
	if totalLen != keyLen {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Total set description field length does not match key length")
	}
	if keyLen > linux.NFT_REG32_COUNT {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Key length is larger than maximum supported register size")
	}
	return concatList[:i], nil
}

// setDescPolicy is the policy for parsing the set description attributes.
// Ref: net/netfilter/nf_tables_api.c:nft_set_desc_policy
var setDescPolicy = []NlaPolicy{
	linux.NFTA_SET_DESC_SIZE:   {nlaType: linux.NLA_U32},
	linux.NFTA_SET_DESC_CONCAT: {nlaType: linux.NLA_NESTED, validator: AttrArrayValidator(setConcatPolicy)},
}

type setDesc struct {
	size   uint32
	concat []uint8
}

// parseSetDescAttr parses the set description attributes.
// Ref: net/netfilter/nf_tables_api.c:nft_set_desc_concat_parse
func parseSetDescAttr(attrs map[uint16]nlmsg.BytesView, keyLen uint32, setFlags uint16) (concat []uint8, descSize uint32, err *syserr.AnnotatedError) {
	descAttrs, ok := attrs[linux.NFTA_SET_DESC]
	if !ok {
		if setFlags&linux.NFT_SET_CONCAT != 0 {
			return nil, 0, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Set concat flag present but set description attribute is missing")
		}
		// The set description attribute is not a required attribute.
		// If the descSize is 0, then the set has no bounds on the number of elements.
		return nil, 0, nil
	}
	subAttrs, ok := NfParseWithOpts(nlmsg.AttrsView(descAttrs), &NfParseOpts{
		Policy: setDescPolicy,
	})
	if !ok {
		return nil, 0, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Failed to parse set description attributes")
	}
	descSize, ok = AttrNetToHost[uint32](linux.NFTA_SET_DESC_SIZE, subAttrs)
	if !ok {
		descSize = 0
	}
	if concatAttrs, ok := subAttrs[linux.NFTA_SET_DESC_CONCAT]; ok {
		concat, err = parseSetConcatAttr(concatAttrs, keyLen)
		if err != nil {
			return nil, 0, err
		}
	}
	if len(concat) > 1 {
		if setFlags&linux.NFT_SET_CONCAT == 0 {
			return nil, 0, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Set concat flag missing but multiple concat elements found")
		}
	} else if setFlags&linux.NFT_SET_CONCAT != 0 {
		return nil, 0, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Set concat flag present but single/no concat elements found")
	}
	return concat, descSize, nil
}

// NewSet creates a set in the given table.
// Ref: net/netfilter/nf_tables_api.c:nf_tables_newset
func (nf *NFTables) NewSet(attrs map[uint16]nlmsg.BytesView, family stack.AddressFamily, msgFlags uint16, ms *nlmsg.MessageSet) *syserr.AnnotatedError {
	tabNameBytes, tabNameOk := attrs[linux.NFTA_SET_TABLE]
	if !tabNameOk {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Set table name attribute is malformed or not found")
	}

	setNameBytes, nameOk := attrs[linux.NFTA_SET_NAME]
	if !nameOk {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Set name attribute is malformed or not found")
	}

	if _, idOk := attrs[linux.NFTA_SET_ID]; !idOk {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Set id attribute is missing")
	}

	keyType, keyTypeOk := AttrNetToHost[uint32](linux.NFTA_SET_KEY_TYPE, attrs)
	if !keyTypeOk {
		keyType = uint32(0)
	}

	keyLen, keyLenOk := AttrNetToHost[uint32](linux.NFTA_SET_KEY_LEN, attrs)
	if !keyLenOk {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Set key length attribute is missing")
	}
	if keyLen == 0 || keyLen > linux.NFT_DATA_VALUE_MAXLEN {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Set key length attribute is invalid")
	}

	setFlagsU32, ok := AttrNetToHost[uint32](linux.NFTA_SET_FLAGS, attrs)
	setFlags := uint16(setFlagsU32)
	if ok {
		if err := validateSetFlags(setFlags); err != nil {
			return err
		}
	}

	dataType, dataLen, err := parseSetDataAttr(attrs, setFlags)
	if err != nil {
		return err
	}

	objType, err := parseSetObjectAttr(attrs, setFlags)
	if err != nil {
		return err
	}

	timeout, err := parseSetTimeoutAttr(attrs, setFlags)
	if err != nil {
		return err
	}

	gcInterval, err := parseSetGCIntervalAttr(attrs, setFlags)
	if err != nil {
		return err
	}

	policy, err := parseSetPolicyAttr(attrs, setFlags)
	if err != nil {
		return err
	}

	descConcat, descSize, err := parseSetDescAttr(attrs, keyLen, setFlags)
	if err != nil {
		return err
	}

	var tab *Table
	if tabNameOk {
		tabName := tabNameBytes.String()
		tab, err = nf.GetTable(family, tabName, uint32(ms.PortID))
		if err != nil {
			return err
		}
	}

	udataAttr, udataExists := attrs[linux.NFTA_SET_USERDATA]
	var udata []byte
	if udataExists {
		udata = []byte(udataAttr)
	}

	if uint32(msgFlags)&linux.NLM_F_CREATE == 0 {
		return syserr.NewAnnotatedError(syserr.ErrNotSupported, "NLM_F_CREATE is required for set creation")
	}

	var exprInfos []ExprInfo
	if singleExpr, ok := attrs[linux.NFTA_SET_EXPR]; ok {
		exprInfo, err := nf.ParseExpr(nlmsg.AttrsView(singleExpr))
		if err != nil {
			return err
		}
		exprInfos = []ExprInfo{*exprInfo}
	} else if exprBytes, ok := attrs[linux.NFTA_SET_EXPRESSIONS]; ok {
		exprInfos, err = nf.ParseNestedExprs(nlmsg.AttrsView(exprBytes), linux.NFT_SET_EXPR_MAX)
		if err != nil {
			return err
		}
	}

	setName := setNameBytes.String()
	newSet := &nftSet{
		name:       setName,
		keyType:    keyType,
		dataType:   dataType,
		objType:    objType,
		descSize:   descSize,
		fieldLen:   descConcat,
		fieldCount: uint8(len(descConcat)),
		timeout:    timeout,
		gcInterval: gcInterval,
		policy:     policy,
		udata:      udata,
		exprInfos:  exprInfos,
		flags:      setFlags,
		dead:       0,
		keyLen:     uint8(keyLen),
		dataLen:    uint8(dataLen),
	}

	if set, exists := tab.sets[setName]; exists {
		if msgFlags&linux.NLM_F_EXCL != 0 {
			return syserr.NewAnnotatedError(syserr.ErrExists, "Set already exists")
		}
		if msgFlags&linux.NLM_F_REPLACE != 0 {
			return syserr.NewAnnotatedError(syserr.ErrNotSupported, "Replace flag is not supported")
		}
		if set.flags&linux.NFT_SET_ANONYMOUS != 0 {
			return syserr.NewAnnotatedError(syserr.ErrNotSupported, "Anonymous set already exists")
		}
		if set.isSame(newSet) {
			return nil
		}
		return syserr.NewAnnotatedError(syserr.ErrExists, "Set already exists with differing attributes")
	}

	if msgFlags&linux.NLM_F_CREATE == 0 {
		return syserr.NewAnnotatedError(syserr.ErrNotSupported, "NLM_F_CREATE is required for set creation")
	}

	// TODO: b/505409691 - Support non-map sets.
	if setFlags&linux.NFT_SET_MAP == 0 {
		return syserr.NewAnnotatedError(syserr.ErrNotSupported, "only map sets are supported yet")
	}

	return nf.addSetToTable(tab, newSet)
}
