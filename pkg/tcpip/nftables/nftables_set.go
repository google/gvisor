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
	"sort"
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/socket/netlink/nlmsg"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip"
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
		concatElem, err := NfParseWithOpts(nlmsg.AttrsView(value), &NfParseOpts{
			Policy: setConcatPolicy,
		})
		if err != nil {
			return nil, err
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
	subAttrs, err := NfParseWithOpts(nlmsg.AttrsView(descAttrs), &NfParseOpts{
		Policy: setDescPolicy,
	})
	if err != nil {
		return nil, 0, err
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

	// Select the set backend based on the set flags.
	// TODO: b/505409691 - Support the remaining non-map set types.
	switch {
	case setFlags&linux.NFT_SET_MAP != 0:
		newSet.backend = nf.newSetMapBackend(int(keyLen), int(dataLen))
	case setFlags&linux.NFT_SET_INTERVAL != 0:
		newSet.backend = nf.newSetIntervalBackend(int(keyLen))
	case setFlags&linux.NFT_SET_TIMEOUT != 0:
		newSet.backend = nf.newSetTimeoutBackend(int(keyLen))
	default:
		return syserr.NewAnnotatedError(syserr.ErrNotSupported, "only map, interval and timeout sets are supported yet")
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
		for _, ops := range set.bindings {
			if validateDataRegister(ops.dregIdx, lenData) != nil {
				return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "Nftables: Data register does not match set data length")
			}
		}
	case linux.NFT_DATA_VERDICT:
		// TODO: b/505409691 - Support validation for verdict lookups.
		// For verdict data, it should check that the jump/gotos
		// are not illegal or out of bounds.
		log.Warningf("Unimplemented: verdict data verification is not supported yet; assuming it is valid.")
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

// commitElement adds a set element to the set backend.
func (s *nftSet) commitElement(elem *nftSetElem, msgFlags uint16) *syserr.AnnotatedError {
	sb := s.backend
	newIdx := len(s.elements)
	existingIdx, err := sb.Add(elem, newIdx)
	if err != nil {
		return err
	}
	// Element was added successfully and no duplicate was found.
	if existingIdx == newIdx {
		s.elements = append(s.elements, *elem)
		return nil
	}
	// Handle existing element.
	if msgFlags&linux.NLM_F_EXCL != 0 {
		return err
	}
	// if NLM_F_EXCL is not set, element should not conflict.
	existingElem := &s.elements[existingIdx]
	if !existingElem.conflicts(elem) {
		return nil
	}
	return syserr.NewAnnotatedError(syserr.ErrExists, "set element already exists")
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
		startKey:    startKey,
		endKey:      endKey,
		intervalEnd: flag&linux.NFT_SET_ELEM_INTERVAL_END != 0,
		timeout:     timeout,
		expiration:  expiration,
		ops:         ops,
		userData:    userData,
		data:        dv,
	}

	if flag&linux.NFT_SET_ELEM_CATCHALL != 0 {
		return set.addCatchAllElement(&newSetElem, msgFlags)
	}
	return set.commitElement(&newSetElem, msgFlags)
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
		elemAttrs, err := NfParseWithOpts(nlmsg.AttrsView(elem), &NfParseOpts{
			Policy: setElemPolicy,
		})
		if err != nil {
			return err
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

	if len(set.bindings) != 0 && (set.flags&linux.NFT_SET_CONSTANT != 0 || set.flags&linux.NFT_SET_ANONYMOUS != 0) {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "set is constant or anonymous and cannot be modified")
	}

	if err := nf.addElemListToSet(nlmsg.AttrsView(elemListAttr), set, tab, flags); err != nil {
		return err
	}
	return nil
}

func (nf *NFTables) dumpSetDescInfo(set *nftSet, tab *Table, family stack.AddressFamily, ms *nlmsg.MessageSet) ([]byte, *syserr.AnnotatedError) {
	m := &nlmsg.Message{}
	if set.descSize != 0 {
		m.PutAttr(linux.NFTA_SET_DESC_SIZE, nlmsg.PutU32(set.descSize))
	}
	if set.fieldCount > 1 {
		var concatList nlmsg.NestedAttr
		for _, concat := range set.fieldLen {
			var concatAttrs nlmsg.NestedAttr
			concatAttrs.PutAttr(linux.NFTA_SET_FIELD_LEN, primitive.AsByteSlice([]byte{concat}))
			concatList.PutAttr(linux.NFTA_LIST_ELEM, primitive.AsByteSlice(concatAttrs))
		}
		m.PutNestedAttr(linux.NFTA_SET_DESC_CONCAT, concatList)
	}
	return m.Buffer(), nil
}

func (nf *NFTables) fillSetInfo(set *nftSet, tab *Table, family stack.AddressFamily, ms *nlmsg.MessageSet) *syserr.AnnotatedError {
	m := ms.AddMessage(linux.NetlinkMessageHeader{
		Type: uint16(linux.NFNL_SUBSYS_NFTABLES)<<8 | uint16(linux.NFT_MSG_NEWSET),
	})
	m.Put(&linux.NetFilterGenMsg{
		Family:  uint8(AfProtocol(tab.GetAddressFamily())),
		Version: uint8(linux.NFNETLINK_V0),
		// Unused, set to 0.
		ResourceID: uint16(0),
	})

	m.PutAttrString(linux.NFTA_SET_TABLE, tab.GetName())
	m.PutAttrString(linux.NFTA_SET_NAME, set.name)
	m.PutAttr(linux.NFTA_SET_HANDLE, nlmsg.PutU64(set.handle))
	if set.flags != 0 {
		m.PutAttr(linux.NFTA_SET_FLAGS, nlmsg.PutU32(uint32(set.flags)))
	}

	m.PutAttr(linux.NFTA_SET_KEY_TYPE, nlmsg.PutU32(set.keyType))
	m.PutAttr(linux.NFTA_SET_KEY_LEN, nlmsg.PutU32(uint32(set.keyLen)))
	if set.flags&linux.NFT_SET_MAP != 0 {
		m.PutAttr(linux.NFTA_SET_DATA_TYPE, nlmsg.PutU32(set.dataType))
		m.PutAttr(linux.NFTA_SET_DATA_LEN, nlmsg.PutU32(uint32(set.dataLen)))
	}
	if set.flags&linux.NFT_SET_OBJECT != 0 {
		m.PutAttr(linux.NFTA_SET_OBJ_TYPE, nlmsg.PutU32(set.objType))
	}
	if set.timeout != 0 {
		m.PutAttr(linux.NFTA_SET_TIMEOUT, nlmsg.PutU64(set.timeout))
	}
	if set.gcInterval != 0 {
		m.PutAttr(linux.NFTA_SET_GC_INTERVAL, nlmsg.PutU32(set.gcInterval))
	}
	if set.policy != linux.NFT_SET_POL_PERFORMANCE {
		m.PutAttr(linux.NFTA_SET_POLICY, nlmsg.PutU32(set.policy))
	}
	if set.udata != nil {
		m.PutAttr(linux.NFTA_SET_USERDATA, primitive.AsByteSlice(set.udata))
	}

	descAttr, err := nf.dumpSetDescInfo(set, tab, family, ms)
	if err != nil {
		return err
	}
	if len(descAttr) > 0 {
		m.PutNestedAttr(linux.NFTA_SET_DESC, descAttr)
	}

	if len(set.exprInfos) == 1 {
		var exprAttr nlmsg.NestedAttr
		exprAttr.PutAttrString(linux.NFTA_EXPR_NAME, set.exprInfos[0].ExprName)
		if len(set.exprInfos[0].ExprData) > 0 {
			exprAttr.PutAttr(linux.NFTA_EXPR_DATA, primitive.AsByteSlice(set.exprInfos[0].ExprData))
		}
		m.PutNestedAttr(linux.NFTA_SET_EXPR, exprAttr)
	} else if len(set.exprInfos) > 1 {
		var exprList nlmsg.NestedAttr
		for _, info := range set.exprInfos {
			var exprAttr nlmsg.NestedAttr
			exprAttr.PutAttrString(linux.NFTA_EXPR_NAME, info.ExprName)
			if len(info.ExprData) > 0 {
				exprAttr.PutAttr(linux.NFTA_EXPR_DATA, primitive.AsByteSlice(info.ExprData))
			}
			exprList.PutAttr(linux.NFTA_LIST_ELEM, primitive.AsByteSlice(exprAttr))
		}
		m.PutNestedAttr(linux.NFTA_SET_EXPRESSIONS, exprList)
	}
	return nil
}

func (nf *NFTables) dumpSets(family stack.AddressFamily, ms *nlmsg.MessageSet) *syserr.AnnotatedError {
	for f := range stack.NumAFs {
		if family != stack.Unspec && f != family {
			continue
		}
		for _, tab := range nf.GetAddressFamilyTables(f) {
			for _, set := range tab.sets {
				if err := nf.fillSetInfo(set, tab, f, ms); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// GetSet handles dumping sets.
// Ref: net/netfilter/nf_tables_api.c:nf_tables_getset()
func (nf *NFTables) GetSet(attrs map[uint16]nlmsg.BytesView, family stack.AddressFamily, flags uint16, ms *nlmsg.MessageSet) *syserr.AnnotatedError {
	if (flags & linux.NLM_F_DUMP) != 0 {
		ms.Multi = true
		return nf.dumpSets(family, ms)
	}
	tableNameBytes, ok := attrs[linux.NFTA_SET_TABLE]
	if !ok {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "set table attribute is missing")
	}
	tableName := tableNameBytes.String()

	table, err := nf.GetTable(family, tableName, uint32(ms.PortID))
	if err != nil {
		return err
	}

	setNameBytes, ok := attrs[linux.NFTA_SET_NAME]
	if !ok {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "set name attribute is missing")
	}
	setName := setNameBytes.String()

	set, ok := table.sets[setName]
	if !ok {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "set does not exist")
	}

	return nf.fillSetInfo(set, table, family, ms)
}

func dumpSetElem(set *nftSet, elem *nftSetElem, isCatchAll bool) (nlmsg.NestedAttr, *syserr.AnnotatedError) {
	var elemAttrs nlmsg.NestedAttr
	if !isCatchAll {
		if len(elem.startKey) > 0 {
			b, err := dumpDataAttr(elem.startKey)
			if err != nil {
				return nil, err
			}
			elemAttrs.PutAttr(linux.NFTA_SET_ELEM_KEY, primitive.AsByteSlice(b))
		}
		if len(elem.endKey) > 0 {
			b, err := dumpDataAttr(elem.endKey)
			if err != nil {
				return nil, err
			}
			elemAttrs.PutAttr(linux.NFTA_SET_ELEM_KEY_END, primitive.AsByteSlice(b))
		}
		if elem.intervalEnd {
			elemAttrs.PutAttr(linux.NFTA_SET_ELEM_FLAGS, nlmsg.PutU32(uint32(linux.NFT_SET_ELEM_INTERVAL_END)))
		}
	} else {
		elemAttrs.PutAttr(linux.NFTA_SET_ELEM_FLAGS, nlmsg.PutU32(uint32(linux.NFT_SET_ELEM_CATCHALL)))
	}

	if (set.flags & linux.NFT_SET_MAP) != 0 {
		var dataDump []byte
		var err *syserr.AnnotatedError
		if elem.data.isVerdict {
			dataDump, err = dumpVerdictDataAttr(elem.data.verdict)
		} else if len(elem.data.data) > 0 {
			dataDump, err = dumpDataAttr(elem.data.data)
		}
		if err != nil {
			return nil, err
		}
		if dataDump != nil {
			elemAttrs.PutAttr(linux.NFTA_SET_ELEM_DATA, primitive.AsByteSlice(dataDump))
		}
	}

	if elem.timeout != 0 {
		elemAttrs.PutAttr(linux.NFTA_SET_ELEM_TIMEOUT, nlmsg.PutU64(elem.timeout))
	}
	if elem.expiration != 0 {
		elemAttrs.PutAttr(linux.NFTA_SET_ELEM_EXPIRATION, nlmsg.PutU64(elem.expiration))
	}
	if len(elem.userData) > 0 {
		elemAttrs.PutAttr(linux.NFTA_SET_ELEM_USERDATA, primitive.AsByteSlice(elem.userData))
	}

	if len(elem.ops) > 0 {
		if len(elem.ops) == 1 {
			opDump, err := elem.ops[0].Dump()
			if err != nil {
				return nil, err
			}
			if opDump != nil {
				elemAttrs.PutAttr(linux.NFTA_SET_ELEM_EXPR, primitive.AsByteSlice(opDump))
			}
		} else {
			var exprList nlmsg.NestedAttr
			for _, op := range elem.ops {
				opDump, err := op.Dump()
				if err != nil {
					return nil, err
				}
				if opDump != nil {
					exprList.PutAttr(linux.NFTA_LIST_ELEM, primitive.AsByteSlice(opDump))
				}
			}
			elemAttrs.PutAttr(linux.NFTA_SET_ELEM_EXPRESSIONS, primitive.AsByteSlice(exprList))
		}
	}
	return elemAttrs, nil
}

// fillSetElemListInfo populates the message set with information about all
// elements in a given set.
// Ref: net/netfilter/nf_tables_api.c:nf_tables_fill_setelem
func (nf *NFTables) fillSetElemListInfo(set *nftSet, tab *Table, family stack.AddressFamily, ms *nlmsg.MessageSet) *syserr.AnnotatedError {
	var elemAttrList nlmsg.NestedAttr

	flushElems := func() {
		m := ms.AddMessage(linux.NetlinkMessageHeader{
			Type:  uint16(linux.NFNL_SUBSYS_NFTABLES)<<8 | uint16(linux.NFT_MSG_NEWSETELEM),
			Flags: linux.NLM_F_MULTI,
		})
		m.Put(&linux.NetFilterGenMsg{
			Family:     uint8(AfProtocol(tab.GetAddressFamily())),
			Version:    uint8(linux.NFNETLINK_V0),
			ResourceID: uint16(0),
		})

		m.PutAttrString(linux.NFTA_SET_ELEM_LIST_TABLE, tab.GetName())
		m.PutAttrString(linux.NFTA_SET_ELEM_LIST_SET, set.name)
		m.PutNestedAttr(linux.NFTA_SET_ELEM_LIST_ELEMENTS, elemAttrList)
		elemAttrList = nil
	}

	// nftables stores interval sets as their raw boundary endpoints and dumps
	// them in ascending key order with the interval-end flag preserved; nft
	// userspace reconstructs the ranges. Non-interval sets dump in insertion
	// order.
	order := make([]int, len(set.elements))
	for i := range order {
		order[i] = i
	}
	if set.flags&linux.NFT_SET_INTERVAL != 0 {
		sort.SliceStable(order, func(a, b int) bool {
			return bytes.Compare(set.elements[order[a]].startKey, set.elements[order[b]].startKey) < 0
		})
	}

	for _, i := range order {
		elemAttrs, err := dumpSetElem(set, &set.elements[i], false)
		if err != nil {
			return err
		}

		// A Netlink attribute header is 4 bytes. The total nested attribute size
		// cannot exceed math.MaxUint16.
		elemSize := linux.NetlinkAttrHeaderSize + len(elemAttrs)
		if len(elemAttrList) > 0 && len(elemAttrList)+elemSize > math.MaxUint16 {
			flushElems()
		}

		elemAttrList.PutAttr(linux.NFTA_LIST_ELEM, primitive.AsByteSlice(elemAttrs))
	}
	if set.catchAllElem != nil {
		elemAttrs, err := dumpSetElem(set, set.catchAllElem, true)
		if err != nil {
			return err
		}

		elemSize := linux.NetlinkAttrHeaderSize + len(elemAttrs)
		if len(elemAttrList) > 0 && len(elemAttrList)+elemSize > math.MaxUint16 {
			flushElems()
		}

		elemAttrList.PutAttr(linux.NFTA_LIST_ELEM, primitive.AsByteSlice(elemAttrs))
	}

	if len(elemAttrList) > 0 {
		flushElems()
	}

	return nil
}

// getSetElem fills the message set with the requested set element.
// Ref: net/netfilter/nf_tables_api.c:nft_get_set_elem
func (nf *NFTables) getSetElem(set *nftSet, table *Table, family stack.AddressFamily, ms *nlmsg.MessageSet, elementsMap map[uint16]nlmsg.BytesView) *syserr.AnnotatedError {
	var foundElem *nftSetElem

	for _, elemViewBytes := range elementsMap {
		elemMap, ok := NfParse(nlmsg.AttrsView(elemViewBytes))
		if !ok {
			return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "failed to parse inner element contents")
		}

		// Parse Catchall
		elemFlagsVal, flagExists := AttrNetToHost[uint32](linux.NFTA_SET_ELEM_FLAGS, elemMap)
		if flagExists && (uint16(elemFlagsVal)&linux.NFT_SET_ELEM_CATCHALL != 0) {
			if set.catchAllElem == nil {
				return syserr.NewAnnotatedError(syserr.ErrNoFileOrDir, "catchall element does not exist in set")
			}
			foundElem = set.catchAllElem
			break
		}

		keyAttr, keyOk := elemMap[linux.NFTA_SET_ELEM_KEY]
		if !keyOk {
			return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "missing key to lookup in element")
		}

		keyMap, ok := NfParse(nlmsg.AttrsView(keyAttr))
		if !ok {
			return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "failed to parse key data attributes for lookup")
		}

		keyData, dataOk := keyMap[linux.NFTA_DATA_VALUE]
		if !dataOk {
			return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "missing data value in key for lookup")
		}

		// Execute lookup and locate matching element.
		idx := set.backend.Find(keyData)
		if idx == -1 {
			return syserr.NewAnnotatedError(syserr.ErrNoFileOrDir, "element does not exist in set")
		}

		foundElem = &set.elements[idx]
		break
	}

	if foundElem == nil {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "no valid element provided in lookup payload")
	}

	elemAttrs, err := dumpSetElem(set, foundElem, foundElem == set.catchAllElem)
	if err != nil {
		return err
	}

	var elemAttrList nlmsg.NestedAttr
	elemAttrList.PutAttr(linux.NFTA_LIST_ELEM, primitive.AsByteSlice(elemAttrs))

	m := ms.AddMessage(linux.NetlinkMessageHeader{
		Type:  uint16(linux.NFNL_SUBSYS_NFTABLES)<<8 | uint16(linux.NFT_MSG_NEWSETELEM),
		Flags: 0,
	})
	m.Put(&linux.NetFilterGenMsg{
		Family:     uint8(AfProtocol(table.GetAddressFamily())),
		Version:    uint8(linux.NFNETLINK_V0),
		ResourceID: uint16(0),
	})

	m.PutAttrString(linux.NFTA_SET_ELEM_LIST_TABLE, table.GetName())
	m.PutAttrString(linux.NFTA_SET_ELEM_LIST_SET, set.name)
	m.PutNestedAttr(linux.NFTA_SET_ELEM_LIST_ELEMENTS, elemAttrList)

	return nil
}

// GetSetElements handles dumping set elements.
// Ref: net/netfilter/nf_tables_api.c:nf_tables_getsetelem
func (nf *NFTables) GetSetElements(attrs map[uint16]nlmsg.BytesView, family stack.AddressFamily, flags uint16, ms *nlmsg.MessageSet) *syserr.AnnotatedError {
	tableNameBytes, tabOk := attrs[linux.NFTA_SET_ELEM_LIST_TABLE]
	if !tabOk {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "set elem list table attribute is missing")
	}

	tableName := tableNameBytes.String()
	table, err := nf.GetTable(family, tableName, uint32(ms.PortID))
	if err != nil {
		return err
	}

	setNameBytes, setOk := attrs[linux.NFTA_SET_ELEM_LIST_SET]
	if !setOk {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "set elem list set attribute is missing")
	}

	setName := setNameBytes.String()
	set, ok := table.sets[setName]
	if !ok {
		return syserr.NewAnnotatedError(syserr.ErrNoFileOrDir, "set does not exist")
	}

	if (flags & linux.NLM_F_DUMP) != 0 {
		ms.Multi = true
		return nf.fillSetElemListInfo(set, table, family, ms)
	}

	// This is a direct lookup (`nf_tables_getsetelem`).
	// We must parse the requested element block to find its key.
	elementsAttr, elementsOk := attrs[linux.NFTA_SET_ELEM_LIST_ELEMENTS]
	if !elementsOk {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "set elem list elements attribute is missing for lookup")
	}

	elementsMap, ok := NfParse(nlmsg.AttrsView(elementsAttr))
	if !ok {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "failed to parse elements wrapper for lookup")
	}
	return nf.getSetElem(set, table, family, ms, elementsMap)
}

// Add set backend implementations below.

// setMapBackend is a backend to handle map operations.
type setMapBackend struct {
	keyLen  int
	dataLen int
	m       map[string]int
}

// Lookup implements NftSetBackend.Lookup.
// The key-register length access should be validated during the set creation.
func (s *setMapBackend) Evaluate(regs *registerSet, keyIdx int) int {
	v, ok := s.m[string(regs.data[keyIdx:keyIdx+s.keyLen])]
	if !ok {
		return -1
	}
	return v
}

// Find implements NftSetBackend.Find.
func (s *setMapBackend) Find(keyData []byte) int {
	if len(keyData) != s.keyLen {
		return -1
	}
	v, ok := s.m[string(keyData)]
	if !ok {
		return -1
	}
	return v
}

// Add implements NftSetBackend.Add.
func (s *setMapBackend) Add(e *nftSetElem, idx int) (int, *syserr.AnnotatedError) {
	if e == nil {
		return -1, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "element is nil")
	}
	if len(e.startKey) != s.keyLen {
		return -1, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "key length does not match set key length")
	}
	key := string(e.startKey)
	if v, ok := s.m[key]; ok {
		return v, nil
	}
	s.m[key] = idx
	return idx, nil
}

// Remove implements NftSetBackend.Remove.
func (s *setMapBackend) Remove(e *nftSetElem) (int, *syserr.AnnotatedError) {
	if e == nil {
		return -1, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "element is nil")
	}
	key := string(e.startKey)
	if v, ok := s.m[key]; ok {
		delete(s.m, key)
		return v, nil
	}
	return -1, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "key not found")
}

// Clone implements NftSetBackend.Clone.
func (s *setMapBackend) Clone() NftSetBackend {
	mCopy := make(map[string]int, len(s.m))
	for k, v := range s.m {
		mCopy[k] = v
	}
	return &setMapBackend{
		keyLen:  s.keyLen,
		dataLen: s.dataLen,
		m:       mCopy,
	}
}

// newSetMapBackend creates a new map backend.
func (nf *NFTables) newSetMapBackend(keyLen int, dataLen int) *setMapBackend {
	return &setMapBackend{
		keyLen:  keyLen,
		dataLen: dataLen,
		m:       make(map[string]int),
	}
}

// setIntervalEndpoint is one boundary in an interval set. nft represents an
// interval set as a sorted sequence of endpoints; a key is a member iff the
// greatest endpoint whose key is <= the lookup key is an interval start (not an
// interval-end marker). This is the half-open [start, end) model used by the
// kernel's rbtree set.
type setIntervalEndpoint struct {
	key   []byte
	isEnd bool // NFT_SET_ELEM_INTERVAL_END: exclusive upper bound of an interval.
	idx   int
}

// setIntervalBackend is a backend for interval sets (NFT_SET_INTERVAL). It
// stores endpoints sorted by key and matches a key when the greatest endpoint
// with key <= the lookup key is an interval start.
//
// Keys are compared as big-endian byte slices, which matches the numeric
// ordering of the network-order ipv4_addr/ipv6_addr keys interval sets use.
type setIntervalBackend struct {
	keyLen    int
	endpoints []setIntervalEndpoint // sorted by key.
}

// search returns the index of the first endpoint whose key is >= the given key.
func (s *setIntervalBackend) search(key []byte) int {
	return sort.Search(len(s.endpoints), func(i int) bool {
		return bytes.Compare(s.endpoints[i].key, key) >= 0
	})
}

// Evaluate implements NftSetBackend.Evaluate.
func (s *setIntervalBackend) Evaluate(regs *registerSet, keyIdx int) int {
	return s.Find(regs.data[keyIdx : keyIdx+s.keyLen])
}

// Find implements NftSetBackend.Find: returns the element index of the
// containing interval's start endpoint, or -1 if the key is not a member.
func (s *setIntervalBackend) Find(keyData []byte) int {
	if len(keyData) != s.keyLen {
		return -1
	}
	// Locate the greatest endpoint whose key is <= keyData.
	pos := s.search(keyData)
	if pos >= len(s.endpoints) || !bytes.Equal(s.endpoints[pos].key, keyData) {
		// No exact match: the candidate is the endpoint just before pos.
		pos--
	}
	if pos < 0 {
		return -1
	}
	if s.endpoints[pos].isEnd {
		return -1
	}
	return s.endpoints[pos].idx
}

// insertEndpoint inserts a single endpoint keeping endpoints sorted by key. If
// an endpoint with the same key already exists, its idx is returned unchanged.
func (s *setIntervalBackend) insertEndpoint(key []byte, isEnd bool, idx int) int {
	pos := s.search(key)
	if pos < len(s.endpoints) && bytes.Equal(s.endpoints[pos].key, key) {
		return s.endpoints[pos].idx
	}
	ep := setIntervalEndpoint{key: slices.Clone(key), isEnd: isEnd, idx: idx}
	s.endpoints = append(s.endpoints, setIntervalEndpoint{})
	copy(s.endpoints[pos+1:], s.endpoints[pos:])
	s.endpoints[pos] = ep
	return idx
}

// removeEndpoint removes the endpoint with the given key, if present.
func (s *setIntervalBackend) removeEndpoint(key []byte) (int, bool) {
	pos := s.search(key)
	if pos < len(s.endpoints) && bytes.Equal(s.endpoints[pos].key, key) {
		idx := s.endpoints[pos].idx
		s.endpoints = append(s.endpoints[:pos], s.endpoints[pos+1:]...)
		return idx, true
	}
	return -1, false
}

// Add implements NftSetBackend.Add.
func (s *setIntervalBackend) Add(e *nftSetElem, idx int) (int, *syserr.AnnotatedError) {
	if e == nil {
		return -1, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "element is nil")
	}
	if len(e.startKey) != s.keyLen {
		return -1, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "key length does not match set key length")
	}
	// nft sends interval bounds as individual endpoints: a start endpoint and a
	// separate NFT_SET_ELEM_INTERVAL_END endpoint (the exclusive upper bound).
	if len(e.endKey) == 0 {
		return s.insertEndpoint(e.startKey, e.intervalEnd, idx), nil
	}
	// Concatenated range form: a single element carrying [startKey, endKey]
	// (both inclusive). Represent it as a start endpoint at startKey and an
	// interval-end endpoint at endKey+1 (exclusive).
	if len(e.endKey) != s.keyLen {
		return -1, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "interval end key length does not match set key length")
	}
	s.insertEndpoint(e.startKey, false, idx)
	if end := incrementKey(e.endKey); end != nil {
		s.insertEndpoint(end, true, idx)
	}
	return idx, nil
}

// Remove implements NftSetBackend.Remove.
func (s *setIntervalBackend) Remove(e *nftSetElem) (int, *syserr.AnnotatedError) {
	if e == nil {
		return -1, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "element is nil")
	}
	idx, ok := s.removeEndpoint(e.startKey)
	if !ok {
		return -1, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "key not found")
	}
	if len(e.endKey) == s.keyLen {
		if end := incrementKey(e.endKey); end != nil {
			s.removeEndpoint(end)
		}
	}
	return idx, nil
}

// Clone implements NftSetBackend.Clone.
func (s *setIntervalBackend) Clone() NftSetBackend {
	c := &setIntervalBackend{
		keyLen:    s.keyLen,
		endpoints: make([]setIntervalEndpoint, len(s.endpoints)),
	}
	for i, ep := range s.endpoints {
		c.endpoints[i] = setIntervalEndpoint{key: slices.Clone(ep.key), isEnd: ep.isEnd, idx: ep.idx}
	}
	return c
}

// newSetIntervalBackend creates a new interval backend.
func (nf *NFTables) newSetIntervalBackend(keyLen int) *setIntervalBackend {
	return &setIntervalBackend{keyLen: keyLen}
}

// incrementKey returns a copy of the big-endian key incremented by one, or nil
// if the key is already the maximum value (all ones), i.e. the interval extends
// to the maximum key.
func incrementKey(key []byte) []byte {
	out := slices.Clone(key)
	for i := len(out) - 1; i >= 0; i-- {
		out[i]++
		if out[i] != 0 {
			return out
		}
	}
	return nil
}

// setTimeoutEntry is a member of a timeout set: an element index plus an
// optional absolute expiry after which the element stops being a member.
type setTimeoutEntry struct {
	idx    int
	expiry tcpip.MonotonicTime
	hasExp bool
}

// setTimeoutBackend is a backend for timeout sets (NFT_SET_TIMEOUT): exact-match
// membership with per-element expiry, as used by dynamically-populated allow
// sets. Expiry is evaluated lazily on lookup against the stack clock.
type setTimeoutBackend struct {
	keyLen int
	clock  tcpip.Clock
	m      map[string]setTimeoutEntry
}

func (s *setTimeoutBackend) expired(e setTimeoutEntry) bool {
	return e.hasExp && !s.clock.NowMonotonic().Before(e.expiry)
}

// Evaluate implements NftSetBackend.Evaluate.
func (s *setTimeoutBackend) Evaluate(regs *registerSet, keyIdx int) int {
	return s.Find(regs.data[keyIdx : keyIdx+s.keyLen])
}

// Find implements NftSetBackend.Find.
func (s *setTimeoutBackend) Find(keyData []byte) int {
	if len(keyData) != s.keyLen {
		return -1
	}
	e, ok := s.m[string(keyData)]
	if !ok || s.expired(e) {
		return -1
	}
	return e.idx
}

// Add implements NftSetBackend.Add.
func (s *setTimeoutBackend) Add(e *nftSetElem, idx int) (int, *syserr.AnnotatedError) {
	if e == nil {
		return -1, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "element is nil")
	}
	if len(e.startKey) != s.keyLen {
		return -1, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "key length does not match set key length")
	}
	key := string(e.startKey)
	if existing, ok := s.m[key]; ok && !s.expired(existing) {
		return existing.idx, nil
	}
	entry := setTimeoutEntry{idx: idx}
	if e.timeout != 0 {
		// nft set-element timeouts are expressed in milliseconds.
		entry.expiry = s.clock.NowMonotonic().Add(time.Duration(e.timeout) * time.Millisecond)
		entry.hasExp = true
	}
	s.m[key] = entry
	return idx, nil
}

// Remove implements NftSetBackend.Remove.
func (s *setTimeoutBackend) Remove(e *nftSetElem) (int, *syserr.AnnotatedError) {
	if e == nil {
		return -1, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "element is nil")
	}
	key := string(e.startKey)
	if existing, ok := s.m[key]; ok {
		delete(s.m, key)
		return existing.idx, nil
	}
	return -1, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "key not found")
}

// Clone implements NftSetBackend.Clone.
func (s *setTimeoutBackend) Clone() NftSetBackend {
	c := &setTimeoutBackend{
		keyLen: s.keyLen,
		clock:  s.clock,
		m:      make(map[string]setTimeoutEntry, len(s.m)),
	}
	for k, v := range s.m {
		c.m[k] = v
	}
	return c
}

// newSetTimeoutBackend creates a new timeout backend.
func (nf *NFTables) newSetTimeoutBackend(keyLen int) *setTimeoutBackend {
	return &setTimeoutBackend{keyLen: keyLen, clock: nf.clock, m: make(map[string]setTimeoutEntry)}
}

