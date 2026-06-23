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
	"bytes"
	"math"
	"slices"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/log"
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

// exprInfoToSetOp converts the given expression information to a set operation.
func exprInfoToSetOp(exprInfo *ExprInfo) (operation, *syserr.AnnotatedError) {
	if exprInfo == nil {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "expression information is nil")
	}
	opType := ToOpType(exprInfo.ExprName)
	if opType == OpTypeUnknown {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "invalid set expression name")
	}
	// TODO - b/505409691: Support quota, and limit ops in Set.
	// Nftables only supports counter, quota, and limit ops in sets.
	switch opType {
	case OpTypeCounter:
		op, err := initCounter(*exprInfo)
		if err != nil {
			return nil, err
		}
		return op, nil
	default:
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "unsupported set expression type")
	}
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
		return syserr.NewAnnotatedError(syserr.ErrNotSupported, "unsupported set flags")
	}
	if (flags & (linux.NFT_SET_MAP | linux.NFT_SET_OBJECT)) ==
		(linux.NFT_SET_MAP | linux.NFT_SET_OBJECT) {
		return syserr.NewAnnotatedError(syserr.ErrNotSupported, "only one of NFT_SET_MAP or NFT_SET_OBJECT is supported")
	}
	if (flags & (linux.NFT_SET_EVAL | linux.NFT_SET_OBJECT)) ==
		(linux.NFT_SET_EVAL | linux.NFT_SET_OBJECT) {
		return syserr.NewAnnotatedError(syserr.ErrNotSupported, "only one of NFT_SET_EVAL or NFT_SET_OBJECT is supported")
	}
	if (flags & (linux.NFT_SET_ANONYMOUS | linux.NFT_SET_TIMEOUT | linux.NFT_SET_EVAL)) ==
		(linux.NFT_SET_ANONYMOUS | linux.NFT_SET_TIMEOUT) {
		return syserr.NewAnnotatedError(syserr.ErrNotSupported, "only one of NFT_SET_ANONYMOUS or NFT_SET_TIMEOUT is supported")
	}
	if (flags & (linux.NFT_SET_CONSTANT | linux.NFT_SET_TIMEOUT)) ==
		(linux.NFT_SET_CONSTANT | linux.NFT_SET_TIMEOUT) {
		return syserr.NewAnnotatedError(syserr.ErrNotSupported, "only one of NFT_SET_CONSTANT or NFT_SET_TIMEOUT is supported")
	}
	return nil
}

// parseSetDataAttr parses the set data type and length attributes.
// Ref: net/netfilter/nf_tables_api.c:nf_tables_newset
func parseSetDataAttr(attrs map[uint16]nlmsg.BytesView, setFlags uint16) (dataType uint32, dataLen uint32, err *syserr.AnnotatedError) {
	dataType, ok := AttrNetToHost[uint32](linux.NFTA_SET_DATA_TYPE, attrs)
	if !ok {
		if setFlags&linux.NFT_SET_MAP != 0 {
			return 0, 0, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "set data type attribute is missing")
		}
		// If the set is not a map, then the data type attribute is not required.
		return 0, 0, nil
	}
	if setFlags&linux.NFT_SET_MAP == 0 {
		return 0, 0, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "set data type attribute should not be present for non-map set")
	}
	if (dataType&linux.NFT_DATA_RESERVED_MASK) == linux.NFT_DATA_RESERVED_MASK &&
		dataType != linux.NFT_DATA_VERDICT {
		return 0, 0, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "unsupported set data type")
	}
	if dataType == linux.NFT_DATA_VERDICT {
		return dataType, 16, nil
	}
	dataLen, ok = AttrNetToHost[uint32](linux.NFTA_SET_DATA_LEN, attrs)
	if !ok {
		return 0, 0, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "set data length attribute is missing")
	}
	if dataLen == 0 || dataLen > linux.NFT_DATA_VALUE_MAXLEN {
		return 0, 0, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "invalid set data length")
	}
	return dataType, dataLen, nil
}

// parseSetObjectAttr parses the set object type attribute.
// Ref: net/netfilter/nf_tables_api.c:nf_tables_newset
func parseSetObjectAttr(attrs map[uint16]nlmsg.BytesView, setFlags uint16) (objType uint32, err *syserr.AnnotatedError) {
	objType, ok := AttrNetToHost[uint32](linux.NFTA_SET_OBJ_TYPE, attrs)
	if ok && (setFlags&linux.NFT_SET_OBJECT == 0) {
		return 0, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "set object flag is not set but object type attribute is present")
	}
	if !ok && (setFlags&linux.NFT_SET_OBJECT != 0) {
		return 0, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "set object flag is set but object type attribute is missing")
	}
	if !ok {
		// The object type attribute is not required if the set is not an object set.
		return linux.NFT_OBJECT_UNSPEC, nil
	}
	if objType == linux.NFT_OBJECT_UNSPEC || objType > linux.NFT_OBJECT_MAX {
		return 0, syserr.NewAnnotatedError(syserr.ErrNotSupported, "invalid set object type")
	}
	return objType, nil
}

// parseSetTimeoutAttr parses the set timeout attribute.
// Ref: net/netfilter/nf_tables_api.c:nf_tables_newset
func parseSetTimeoutAttr(attrs map[uint16]nlmsg.BytesView, setFlags uint16) (timeMiliSec uint64, err *syserr.AnnotatedError) {
	timeMS, ok := AttrNetToHost[uint64](linux.NFTA_SET_TIMEOUT, attrs)
	if ok && (setFlags&linux.NFT_SET_TIMEOUT == 0) {
		return 0, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "set timeout flag is not set but timeout attribute is present")
	}
	if !ok {
		// The timeout attribute is not a required attribute.
		return 0, nil
	}
	if setFlags&linux.NFT_SET_ANONYMOUS != 0 {
		return 0, syserr.NewAnnotatedError(syserr.ErrNotSupported, "set timeout flag is not supported for anonymous sets")
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
		return 0, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "set gc flag is not set but gc attribute is present")
	}
	if setFlags&linux.NFT_SET_ANONYMOUS != 0 {
		return 0, syserr.NewAnnotatedError(syserr.ErrNotSupported, "set gc flag is not supported for anonymous sets")
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
		return 0, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "invalid set policy")
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
			return nil, syserr.NewAnnotatedError(syserr.ErrFileTooBig, "too many set description concat elements")
		}
		hdr, value, rest, ok := concatAttrsList.ParseFirst()
		if !ok {
			return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "failed to parse set description concat element")
		}
		concatAttrsList = rest
		if hdr.Type != linux.NFTA_LIST_ELEM {
			return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "set description concat element is not of type NFTA_LIST_ELEM")
		}
		concatElem, ok := NfParseWithOpts(nlmsg.AttrsView(value), &NfParseOpts{
			Policy: setConcatPolicy,
		})
		if !ok {
			return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "failed to parse set description concat element attributes")
		}
		fieldLen, ok := AttrNetToHost[uint32](linux.NFTA_SET_FIELD_LEN, concatElem)
		if !ok {
			return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "failed to parse set description field length")
		}
		if fieldLen == 0 || fieldLen > math.MaxUint8 {
			return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "invalid set field length")
		}

		concatList[i] = uint8(fieldLen)
		i++
		totalLen += roundUpToNearestMultipleOfFour(fieldLen)
	}
	if totalLen != keyLen {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "total set description field length does not match key length")
	}
	if keyLen > linux.NFT_REG32_COUNT {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "key length is larger than maximum supported register size")
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
			return nil, 0, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "set concat flag present but set description attribute is missing")
		}
		// The set description attribute is not a required attribute.
		// If the descSize is 0, then the set has no bounds on the number of elements.
		return nil, 0, nil
	}
	subAttrs, ok := NfParseWithOpts(nlmsg.AttrsView(descAttrs), &NfParseOpts{
		Policy: setDescPolicy,
	})
	if !ok {
		return nil, 0, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "failed to parse set description attributes")
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
			return nil, 0, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "set concat flag missing but multiple concat elements found")
		}
	} else if setFlags&linux.NFT_SET_CONCAT != 0 {
		return nil, 0, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "set concat flag present but single/no concat elements found")
	}
	return concat, descSize, nil
}

// NewSet creates a set in the given table.
// Ref: net/netfilter/nf_tables_api.c:nf_tables_newset
func (nf *NFTables) NewSet(attrs map[uint16]nlmsg.BytesView, family stack.AddressFamily, msgFlags uint16, ms *nlmsg.MessageSet) *syserr.AnnotatedError {
	tabNameBytes, tabNameOk := attrs[linux.NFTA_SET_TABLE]
	if !tabNameOk {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "set table name attribute is malformed or not found")
	}

	setNameBytes, nameOk := attrs[linux.NFTA_SET_NAME]
	if !nameOk {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "set name attribute is malformed or not found")
	}

	if _, idOk := attrs[linux.NFTA_SET_ID]; !idOk {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "set id attribute is missing")
	}

	keyType, keyTypeOk := AttrNetToHost[uint32](linux.NFTA_SET_KEY_TYPE, attrs)
	if !keyTypeOk {
		keyType = uint32(0)
	}

	keyLen, keyLenOk := AttrNetToHost[uint32](linux.NFTA_SET_KEY_LEN, attrs)
	if !keyLenOk {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "set key length attribute is missing")
	}
	if keyLen == 0 || keyLen > linux.NFT_DATA_VALUE_MAXLEN {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "set key length attribute is invalid")
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
			return syserr.NewAnnotatedError(syserr.ErrExists, "set already exists")
		}
		if msgFlags&linux.NLM_F_REPLACE != 0 {
			return syserr.NewAnnotatedError(syserr.ErrNotSupported, "replace flag is not supported")
		}
		if set.flags&linux.NFT_SET_ANONYMOUS != 0 {
			return syserr.NewAnnotatedError(syserr.ErrNotSupported, "anonymous set already exists")
		}
		if set.isSame(newSet) {
			return nil
		}
		return syserr.NewAnnotatedError(syserr.ErrExists, "set already exists with differing attributes")
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

// nftSetExprPolicy is the policy for parsing the set expression attributes.
// Ref: net/netfilter/nf_tables_api.c:nft_set_expr_policy
var nftSetExprPolicy = []NlaPolicy{
	linux.NFTA_EXPR_NAME: {nlaType: linux.NLA_STRING},
	linux.NFTA_EXPR_DATA: {nlaType: linux.NLA_NESTED},
}

// setElemPolicy is the policy for parsing the set element attributes.
// Ref: net/netfilter/nf_tables_api.c:nft_set_elem_policy
var setElemPolicy = []NlaPolicy{
	linux.NFTA_SET_ELEM_KEY:         {nlaType: linux.NLA_NESTED},
	linux.NFTA_SET_ELEM_DATA:        {nlaType: linux.NLA_NESTED},
	linux.NFTA_SET_ELEM_FLAGS:       {nlaType: linux.NLA_U32},
	linux.NFTA_SET_ELEM_TIMEOUT:     {nlaType: linux.NLA_U64},
	linux.NFTA_SET_ELEM_EXPIRATION:  {nlaType: linux.NLA_U64},
	linux.NFTA_SET_ELEM_USERDATA:    {nlaType: linux.NLA_BINARY, validator: AttrMaxLenValidator(linux.NFT_USERDATA_MAXLEN - 1)},
	linux.NFTA_SET_ELEM_EXPR:        {nlaType: linux.NLA_NESTED},
	linux.NFTA_SET_ELEM_OBJREF:      {nlaType: linux.NLA_STRING, validator: AttrMaxLenValidator(linux.NFT_OBJ_MAXNAMELEN - 1)},
	linux.NFTA_SET_ELEM_KEY_END:     {nlaType: linux.NLA_NESTED},
	linux.NFTA_SET_ELEM_EXPRESSIONS: {nlaType: linux.NLA_NESTED, validator: AttrArrayValidator(nftSetExprPolicy)},
}

// setElemListPolicy is the policy for parsing the set element list attributes.
// Ref: net/netfilter/nf_tables_api.c:nft_set_elem_list_policy
var setElemListPolicy = []NlaPolicy{
	linux.NFTA_SET_ELEM_LIST_TABLE:    {nlaType: linux.NLA_STRING, validator: AttrMaxLenValidator(linux.NFT_TABLE_MAXNAMELEN - 1)},
	linux.NFTA_SET_ELEM_LIST_SET:      {nlaType: linux.NLA_STRING, validator: AttrMaxLenValidator(linux.NFT_SET_MAXNAMELEN - 1)},
	linux.NFTA_SET_ELEM_LIST_ELEMENTS: {nlaType: linux.NLA_NESTED, validator: AttrArrayValidator(setElemPolicy)},
	linux.NFTA_SET_ELEM_LIST_SET_ID:   {nlaType: linux.NLA_U32},
}

// validateElemFlags validates the set element flags.
// Ref: net/netfilter/nf_tables_api.c:nft_setelem_parse_flags
func (nf *NFTables) validateElemFlags(setFlags uint16, elemFlags uint16) *syserr.AnnotatedError {
	if elemFlags & ^(linux.NFT_SET_ELEM_INTERVAL_END|linux.NFT_SET_ELEM_CATCHALL) != 0 {
		return syserr.NewAnnotatedError(syserr.ErrNotSupported, "unsupported set element flags")
	}
	if (setFlags&linux.NFT_SET_INTERVAL) == 0 &&
		(elemFlags&linux.NFT_SET_ELEM_INTERVAL_END != 0) {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "interval end flag is only supported for interval sets")
	}
	if (elemFlags & (linux.NFT_SET_ELEM_INTERVAL_END | linux.NFT_SET_ELEM_CATCHALL)) ==
		(linux.NFT_SET_ELEM_INTERVAL_END | linux.NFT_SET_ELEM_CATCHALL) {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "interval end and catchall flags cannot be set at the same time")
	}
	return nil
}

// parseElemKeyAttr parses the set element key attribute.
// Ref: net/netfilter/nf_tables_api.c:nft_setelem_parse_key
func (nf *NFTables) parseElemKeyAttr(attrs nlmsg.BytesView, setKeyLen int) ([]byte, *syserr.AnnotatedError) {
	keyDataAttrs, ok := NfParse(nlmsg.AttrsView(attrs))
	if !ok {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "failed to parse key attributes")
	}
	keyBytes, err := parseDataAttrs(keyDataAttrs)
	if err != nil {
		return nil, err
	}
	if len(keyBytes) != int(setKeyLen) {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "key length does not match set key length")
	}
	return keyBytes, nil
}

func (nf *NFTables) parseElemDataAttr(tab *Table, set *nftSet, dataAttrs nlmsg.BytesView) (*dataOrVerdict, *syserr.AnnotatedError) {
	dv := &dataOrVerdict{}
	dataValueAttr, ok := NfParse(nlmsg.AttrsView(dataAttrs))
	if !ok {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "failed to parse set element data attribute")
	}

	var dataValue []byte
	var verdict stack.NFVerdict
	dataType := linux.NFT_DATA_VALUE
	if b, err := parseDataAttrs(dataValueAttr); err == nil {
		dataValue = b
	} else if v, err := parseVerdictAttrs(tab, dataValueAttr); err == nil {
		verdict = v
		dataType = linux.NFT_DATA_VERDICT
	} else {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "failed to parse set element data attribute")
	}

	switch dataType {
	case linux.NFT_DATA_VALUE:
		lenData := len(dataValue)
		if lenData != int(set.dataLen) {
			return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "data length does not match set data length")
		}
	case linux.NFT_DATA_VERDICT:
		// TODO: b/505409691 - Fix this check for vmaps.
		log.Warningf("Unimplemented: vmap verification is not supported yet; assuming it is valid.")
	}
	dv.data = dataValue
	dv.verdict = verdict
	dv.isVerdict = dataType == linux.NFT_DATA_VERDICT
	return dv, nil
}

// conflicts checks if the set element data/verdict clashes with the other set element.
// Ref: net/netfilter/nf_tables_api.c duplicate clash detection logic.
func (e *nftSetElem) conflicts(other *nftSetElem) bool {
	if e.data.isVerdict != other.data.isVerdict ||
		e.data.verdict != other.data.verdict ||
		!bytes.Equal(e.data.data, other.data.data) {
		return true
	}
	// TODO: b/505409691 - Compare objref when supported.
	return false
}

// addCatchallElement adds a catchall element to the set.
// Ref: net/netfilter/nf_tables_api.c:nft_add_set_elem
func (s *nftSet) addCatchAllElement(elem *nftSetElem, msgFlags uint16) *syserr.AnnotatedError {
	catchAllElem := s.catchAllElem
	if catchAllElem == nil {
		s.catchAllElem = elem
		return nil
	}
	if msgFlags&linux.NLM_F_EXCL != 0 {
		return syserr.NewAnnotatedError(syserr.ErrExists, "catchall element already exists")
	}
	if !catchAllElem.conflicts(elem) {
		return nil
	}
	return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "catchall element already exists and is not the same")
}

// addElemToSet adds a set element to a set.
// Ref: net/netfilter/nf_tables_api.c:nft_add_set_elem
func (nf *NFTables) addElemToSet(tab *Table, set *nftSet, elemAttrs map[uint16]nlmsg.BytesView, msgFlags uint16) *syserr.AnnotatedError {
	// If the set has a desc size, check if the set is full.
	// Otherwise, allow any number of elements to be added to the set.
	// Ref: net/netfilter/nf_tables_api.c:nft_set_maxsize
	if set.descSize > 0 && len(set.elements) >= int(set.descSize) {
		return syserr.NewAnnotatedError(syserr.ErrTooManyOpenFiles, "set element limit reached")
	}

	flagU32, flagExists := AttrNetToHost[uint32](linux.NFTA_SET_ELEM_FLAGS, elemAttrs)
	if !flagExists {
		flagU32 = uint32(0)
	}
	flag := uint16(flagU32)

	if err := nf.validateElemFlags(set.flags, flag); err != nil {
		return err
	}

	keyStartAttr, keyExists := elemAttrs[linux.NFTA_SET_ELEM_KEY]
	if keyExists && (flag&linux.NFT_SET_ELEM_CATCHALL != 0) {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "set element key attribute should not be present for catchall element")
	}
	if !keyExists && (flag&linux.NFT_SET_ELEM_CATCHALL == 0) {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "set element key attribute is missing for non-catchall element")
	}

	dataAttr, dataExists := elemAttrs[linux.NFTA_SET_ELEM_DATA]
	if (set.flags & linux.NFT_SET_MAP) != 0 {
		if !dataExists && (flag&linux.NFT_SET_ELEM_INTERVAL_END == 0) {
			return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "set element data attribute is missing for non-interval element")
		}
	} else if dataExists {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "set element data attribute should not be present for non-map set")
	}

	_, objRefExists := elemAttrs[linux.NFTA_SET_ELEM_OBJREF]
	if (set.flags & linux.NFT_SET_OBJECT) != 0 {
		if !objRefExists && (flag&linux.NFT_SET_ELEM_INTERVAL_END == 0) {
			return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "set element object reference attribute is missing for non-interval element")
		}
	} else if objRefExists {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "set element object reference attribute should not be present for non-object set")
	}

	if (flag&linux.NFT_SET_ELEM_INTERVAL_END) != 0 &&
		(dataExists ||
			objRefExists ||
			elemAttrs[linux.NFTA_SET_ELEM_TIMEOUT] != nil ||
			elemAttrs[linux.NFTA_SET_ELEM_EXPIRATION] != nil ||
			elemAttrs[linux.NFTA_SET_ELEM_USERDATA] != nil ||
			elemAttrs[linux.NFTA_SET_ELEM_EXPR] != nil ||
			elemAttrs[linux.NFTA_SET_ELEM_KEY_END] != nil ||
			elemAttrs[linux.NFTA_SET_ELEM_EXPRESSIONS] != nil) {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "interval end flag is set but interval end attributes are missing")
	}

	// TODO: b/505409691 - Add support for timeout and gc.
	timeout, ok := AttrNetToHost[uint64](linux.NFTA_SET_ELEM_TIMEOUT, elemAttrs)
	if ok {
		if (set.flags & linux.NFT_SET_TIMEOUT) == 0 {
			return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "timeout flag is not set but timeout attribute is present")
		}
	} else if (set.flags&linux.NFT_SET_TIMEOUT) != 0 && (flag&linux.NFT_SET_ELEM_INTERVAL_END) == 0 {
		timeout = set.timeout
	}

	// TODO: b/505409691 - Add support for expiration.
	expiration, ok := AttrNetToHost[uint64](linux.NFTA_SET_ELEM_EXPIRATION, elemAttrs)
	if ok {
		if (set.flags & linux.NFT_SET_TIMEOUT) == 0 {
			return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "expiration flag is not set but expiration attribute is present")
		}
		if timeout == 0 {
			return syserr.NewAnnotatedError(syserr.ErrNotSupported, "expiration attribute present but timeout is zero")
		}
		if expiration > timeout {
			return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "expiration time is greater than timeout")
		}
	}

	var exprInfos []ExprInfo
	var err *syserr.AnnotatedError
	expr, ok := elemAttrs[linux.NFTA_SET_ELEM_EXPR]
	if ok {
		if len(set.exprInfos) > 0 && len(set.exprInfos) != 1 {
			return syserr.NewAnnotatedError(syserr.ErrNotSupported, "only one expression is supported for set element expression")
		}
		exprInfo, err := nf.ParseExpr(nlmsg.AttrsView(expr))
		if err != nil {
			return err
		}
		exprInfos = []ExprInfo{*exprInfo}
	} else {
		exprListAttr, ok := elemAttrs[linux.NFTA_SET_ELEM_EXPRESSIONS]
		if ok {
			exprInfos, err = nf.ParseNestedExprs(nlmsg.AttrsView(exprListAttr), linux.NFT_SET_EXPR_MAX)
			if err != nil {
				return err
			}
		}
	}

	if len(exprInfos) > 0 && len(set.exprInfos) > 0 {
		if len(exprInfos) != len(set.exprInfos) {
			return syserr.NewAnnotatedError(syserr.ErrNotSupported, "number of set element expressions does not match number of set operations")
		}
		for i, exprInfo := range exprInfos {
			if exprInfo.ExprName != set.exprInfos[i].ExprName {
				return syserr.NewAnnotatedError(syserr.ErrNotSupported, "set element expression operation does not match set operation")
			}
		}
	} else if len(set.exprInfos) != 0 && (flag&linux.NFT_SET_ELEM_INTERVAL_END) == 0 {
		exprInfos = set.exprInfos
	}

	// Convert expressions to operations to execute at evaluation time.
	// Each element has it's private set of operations to execute at evaluation time.
	// Ref: net/netfilter/nf_tables_api.c:nft_set_elem_expr_clone
	var ops []operation
	if len(exprInfos) != 0 {
		ops = make([]operation, len(exprInfos))
	}
	for i, ei := range exprInfos {
		var err *syserr.AnnotatedError
		ops[i], err = exprInfoToSetOp(&ei)
		if err != nil {
			return err
		}
	}

	var startKey []byte
	setKeyLen := int(set.keyLen)
	if keyExists {
		startKey, err = nf.parseElemKeyAttr(keyStartAttr, setKeyLen)
		if err != nil {
			return err
		}
	}

	endKeyAttr, endKeyExists := elemAttrs[linux.NFTA_SET_ELEM_KEY_END]
	var endKey []byte
	if endKeyExists {
		endKey, err = nf.parseElemKeyAttr(endKeyAttr, setKeyLen)
		if err != nil {
			return err
		}
	}

	if objRefExists {
		// TODO: b/505409691 - Support object reference attribute.
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "object reference attribute is not supported")
	}

	var dv dataOrVerdict
	if dataExists {
		parsedDv, err := nf.parseElemDataAttr(tab, set, dataAttr)
		if err != nil {
			return err
		}
		dv = *parsedDv
	}

	var userData []byte
	userDataAttr, userDataExists := elemAttrs[linux.NFTA_SET_ELEM_USERDATA]
	if userDataExists {
		userData = slices.Clone([]byte(userDataAttr))
	}

	newSetElem := nftSetElem{
		startKey:   startKey,
		endKey:     endKey,
		timeout:    timeout,
		expiration: expiration,
		ops:        ops,
		userData:   userData,
		data:       dv,
	}

	if flag&linux.NFT_SET_ELEM_CATCHALL != 0 {
		return set.addCatchAllElement(&newSetElem, msgFlags)
	}
	set.elements = append(set.elements, newSetElem)
	return nil
}

// addElemListToSet adds a list of elements to a set.
// Ref: net/netfilter/nf_tables_api.c:nf_tables_newsetelem
func (nf *NFTables) addElemListToSet(attr nlmsg.AttrsView, set *nftSet, tab *Table, msgFlags uint16) *syserr.AnnotatedError {
	for len(attr) > 0 {
		_, elem, rest, ok := attr.ParseFirst()
		if !ok {
			return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "failed to parse set elem list attributes")
		}
		attr = rest
		elemAttrs, ok := NfParseWithOpts(nlmsg.AttrsView(elem), &NfParseOpts{
			Policy: setElemPolicy,
		})
		if !ok {
			return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "failed to parse set element attributes")
		}
		if err := nf.addElemToSet(tab, set, elemAttrs, msgFlags); err != nil {
			return err
		}
	}
	return nil
}

// NewSetElements is a top level function to create
// a new set with a list of elements.
// Ref: net/netfilter/nf_tables_api.c:nf_tables_newsetelem()
func (nf *NFTables) NewSetElements(attrs map[uint16]nlmsg.BytesView, family stack.AddressFamily, flags uint16, ms *nlmsg.MessageSet) *syserr.AnnotatedError {
	elemListAttr, ok := attrs[linux.NFTA_SET_ELEM_LIST_ELEMENTS]
	if !ok {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "set elem list elements attribute is missing")
	}

	tabNameBytes, ok := attrs[linux.NFTA_SET_ELEM_LIST_TABLE]
	if !ok {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "set elem list table attribute is missing")
	}
	tabName := tabNameBytes.String()

	tab, err := nf.GetTable(family, tabName, uint32(ms.PortID))
	if err != nil {
		return err
	}

	setNameBytes, ok := attrs[linux.NFTA_SET_ELEM_LIST_SET]
	if !ok {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "set elem list set attribute is missing")
	}
	setName := setNameBytes.String()
	var set *nftSet
	if set, ok = tab.sets[setName]; !ok {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "set does not exist")
	}

	if err := nf.addElemListToSet(nlmsg.AttrsView(elemListAttr), set, tab, flags); err != nil {
		return err
	}
	return nil
}
