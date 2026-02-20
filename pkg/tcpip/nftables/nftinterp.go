// Copyright 2024 The gVisor Authors.
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
	"encoding/hex"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// SyntaxError is an interpretation error due to incorrect syntax.
type SyntaxError struct {
	// lnIdx is the index of the line where the error occurred.
	lnIdx int
	// tkIdx is the index of the token where the error occurred.
	tkIdx int
	// msg is the error message, defined locally.
	msg string
}

// Error implements error interface for SyntaxError to return an error message.
func (e *SyntaxError) Error() string {
	// Adds 1 to line index and token index to account for 0-indexing.
	return fmt.Sprintf("syntax error at line %d, token %d: %s", e.lnIdx+1, e.tkIdx+1, e.msg)
}

// LogicError is an interpretation error from modifying the NFTables state.
type LogicError struct {
	// lnIdx is the index of the line where the error occurred.
	lnIdx int
	// tkIdx is the index of the token where the error occurred.
	tkIdx int
	// error is the error returned from modifying the NFTables state.
	err error
}

// Error implements error interface for LogicError to return an error message.
func (e *LogicError) Error() string {
	// Adds 1 to line index and token index to account for 0-indexing.
	return fmt.Sprintf("logic error at line %d, token %d: %v", e.lnIdx+1, e.tkIdx+1, e.err)
}

// Note: this is a limited set of keywords.
var reservedKeywords []string = []string{
	"include",                        // include keyword
	"define", "undefine", "redefine", // symbolic variables keywords
	"ip", "ip6", "inet", "arp", "bridge", "netdev", // address families
	"list", "flush", "ruleset", // ruleset operations
	"add", "create", "delete", "destroy", "table", "comment", "flags", "handle", // table operations
	"rename", "chain", "type", "hook", "device", "priority", "policy", // chain operations
	"insert", "reset", "replace", "rule", "index", // rule operations
}

// Set of reserved specifiers for quick lookup.
var reservedKeywordSet map[string]struct{} = initReservedKeywordSet()

func initReservedKeywordSet() map[string]struct{} {
	set := make(map[string]struct{})
	for _, k := range reservedKeywords {
		set[k] = struct{}{}
	}
	return set
}

var identifierRegexp = regexp.MustCompile("^[a-zA-Z_][a-zA-Z0-9_/.]*$")

// validateIdentifier checks if the identifier is valid.
// An identifier is valid if it is not a reserved keyword and begins with an
// alphabetic character or underscore followed by zero or more alphanumeric
// characters, underscores, forward slashes, or periods.
func validateIdentifier(id string, lnIdx int, tkIdx int) *syserr.AnnotatedError {
	if _, ok := reservedKeywordSet[id]; ok {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("cannot use reserved keyword: %s", id))
	}

	if !identifierRegexp.MatchString(id) {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("invalid identifier: %s", id))
	}

	return nil
}

// InterpretRule creates a new Rule from the given rule string, assumed to be
// represented as a block of text with a single operation per line.
// Note: the rule string should be generated as output from the official nft
// binary (can be accomplished by using flag --debug=netlink).
func InterpretRule(ruleString string) (*Rule, *syserr.AnnotatedError) {
	ruleString = strings.TrimSpace(ruleString)
	lines := slices.DeleteFunc(strings.Split(ruleString, "\n"), func(s string) bool {
		return s == ""
	})

	r := &Rule{ops: make([]operation, 0, len(lines))}

	// Interprets all operations in the rule.
	for lnIdx, line := range lines {
		op, err := InterpretOperation(line, lnIdx)
		if err != nil {
			return nil, err
		}
		if err := r.addOperation(op); err != nil {
			return nil, err
		}
	}

	return r, nil
}

// InterpretOperation creates a new operation from the given operation string,
// assumed to be a single line of text surrounded in square brackets.
// Note: the operation string should be generated as output from the official nft
// binary (can be accomplished by using flag --debug=netlink).
func InterpretOperation(line string, lnIdx int) (operation, *syserr.AnnotatedError) {
	tokens := strings.Fields(line)

	// TODO: b/421437663 - This should be done on validation of every operation type.
	if len(tokens) < 2 {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("incorrect number of tokens for operation, should be at least 2, got %d", len(tokens)))
	}

	// TODO: b/421437663 - Replace this to interpret byte code to create these operations.
	// Can also refactor this so that operations are registered dynamically instead of being updated
	// here, using an init function per nft_{operation}.go file.
	// Error values from net/netfilter/nf_tables_api.c:nft_expr_type_get
	// Second token decides the operation type.
	switch tokens[1] {
	case "immediate":
		return InterpretImmediate(line, lnIdx)
	case "cmp":
		return InterpretComparison(line, lnIdx)
	case "payload":
		switch tokens[2] {
		case "load":
			return InterpretPayloadLoad(line, lnIdx)
		case "write":
			return InterpretPayloadSet(line, lnIdx)
		}
		return nil, syserr.NewAnnotatedError(syserr.ErrNoFileOrDir, fmt.Sprintf("invalid payload operation: %s", tokens[2]))
	case "bitwise":
		// Assumes the bitwise operation is a boolean because interpretation of
		// non-boolean operations is not supported from the nft binary debug output.
		return InterpretBitwiseBool(line, lnIdx)
	case "counter":
		return InterpretCounter(line, lnIdx)
	case "rt":
		return InterpretRoute(line, lnIdx)
	case "byteorder":
		return InterpretByteorder(line, lnIdx)
	case "meta":
		switch tokens[2] {
		case "load":
			return InterpretMetaLoad(line, lnIdx)
		case "set":
			return InterpretMetaSet(line, lnIdx)
		}
		return nil, syserr.NewAnnotatedError(syserr.ErrNoFileOrDir, fmt.Sprintf("invalid meta operation: %s", tokens[2]))
	default:
		return nil, syserr.NewAnnotatedError(syserr.ErrNoFileOrDir, fmt.Sprintf("invalid operation: %s", tokens[1]))
	}
}

// InterpretImmediate creates a new Immediate operation from the given string.
func InterpretImmediate(line string, lnIdx int) (operation, *syserr.AnnotatedError) {
	tokens := strings.Fields(line)

	// Requires at least 6 tokens:
	// 		"[", "immediate", "reg", register index, register value, "]".
	if len(tokens) < 6 {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("incorrect number of tokens for immediate operation, should be at least 6, got %d", len(tokens)))
	}

	if err := checkOperationBrackets(tokens, lnIdx); err != nil {
		return nil, err
	}

	tkIdx := 1

	// First token should be "immediate".
	if err := consumeToken("immediate", tokens, lnIdx, tkIdx); err != nil {
		return nil, err
	}
	tkIdx++

	// Second token should be "reg".
	if err := consumeToken("reg", tokens, lnIdx, tkIdx); err != nil {
		return nil, err
	}
	tkIdx++

	// Third token should be the uint8 representing the register index.
	reg, err := parseRegister(tokens[tkIdx], lnIdx, tkIdx)
	if err != nil {
		return nil, err
	}
	tkIdx++

	// Fourth token should be the value.
	nextIdx, data, err := parseRegisterData(reg, tokens, lnIdx, tkIdx)
	if err != nil {
		return nil, err
	}
	tkIdx = nextIdx

	// Done parsing tokens.
	if tkIdx != len(tokens)-1 {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "unexpected token after immediate operation")
	}

	// Create the operation with the specified arguments.
	imm, err := newImmediate(reg, data)
	if err != nil {
		return nil, err
	}

	return imm, nil
}

// InterpretComparison creates a new Comparison operation from the given string.
func InterpretComparison(line string, lnIdx int) (operation, *syserr.AnnotatedError) {
	tokens := strings.Fields(line)

	// Requires at least 7 tokens:
	// 		"[", "cmp", op, "reg", register index, register value, "]".
	if len(tokens) < 7 {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("incorrect number of tokens for comparison operation, should be at least 7, got %d", len(tokens)))
	}

	if err := checkOperationBrackets(tokens, lnIdx); err != nil {
		return nil, err
	}

	tkIdx := 1

	// First token should be "cmp".
	if err := consumeToken("cmp", tokens, lnIdx, tkIdx); err != nil {
		return nil, err
	}
	tkIdx++

	// Second token should be the comparison operator.
	cop, err := parseCmpOp(tokens[tkIdx], lnIdx, tkIdx)
	if err != nil {
		return nil, err
	}
	tkIdx++

	// Third token should be "reg".
	if err := consumeToken("reg", tokens, lnIdx, tkIdx); err != nil {
		return nil, err
	}
	tkIdx++

	// Fourth token should be the uint8 representing the register index.
	reg, err := parseRegister(tokens[tkIdx], lnIdx, tkIdx)
	if err != nil {
		return nil, err
	}
	tkIdx++

	// Fifth token should be the bytesData representing the value.
	nextIdx, data, err := parseHexData(tokens, lnIdx, tkIdx)
	if err != nil {
		return nil, err
	}
	tkIdx = nextIdx

	// Done parsing tokens.
	if tkIdx != len(tokens)-1 {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "unexpected token after comparison operation")
	}

	// Create the operation with the specified arguments.
	cmp, err := newComparison(reg, cop, data)
	if err != nil {
		return nil, err
	}

	return cmp, nil
}

// InterpretPayloadLoad creates a new PayloadLoad operation from the given
// string.
func InterpretPayloadLoad(line string, lnIdx int) (operation, *syserr.AnnotatedError) {
	tokens := strings.Fields(line)

	// Requires exactly 13 tokens:
	// 		"[", "payload", "load", len+"b", "@", payload base, "header", "+", offset, "=>", "reg", register index, "]".
	if len(tokens) != 13 {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("incorrect number of tokens for payload load operation, should be 13, got %d", len(tokens)))
	}

	if err := checkOperationBrackets(tokens, lnIdx); err != nil {
		return nil, err
	}

	tkIdx := 1

	// First token should be "payload".
	if err := consumeToken("payload", tokens, lnIdx, tkIdx); err != nil {
		return nil, err
	}
	tkIdx++

	// Second token should be "load".
	if err := consumeToken("load", tokens, lnIdx, tkIdx); err != nil {
		return nil, err
	}
	tkIdx++

	// Third token should be the length (in bytes) of the payload followed by 'b'.
	blen, err := parseUint8PlusChar(tokens[tkIdx], 'b', lnIdx, tkIdx)
	if err != nil {
		return nil, err
	}
	tkIdx++

	// Fourth token should be "@".
	if err := consumeToken("@", tokens, lnIdx, tkIdx); err != nil {
		return nil, err
	}
	tkIdx++

	// Fifth token should be the payload base header.
	base, err := parsePayloadBase(tokens[tkIdx], lnIdx, tkIdx)
	if err != nil {
		return nil, err
	}
	tkIdx++

	// Sixth token should be "header".
	if err := consumeToken("header", tokens, lnIdx, tkIdx); err != nil {
		return nil, err
	}
	tkIdx++

	// Seventh token should be "+".
	if err := consumeToken("+", tokens, lnIdx, tkIdx); err != nil {
		return nil, err
	}
	tkIdx++

	// Eighth token should be the uint8 representing the offset.
	offset, err := parseUint8(tokens[tkIdx], "offset", lnIdx, tkIdx)
	if err != nil {
		return nil, err
	}
	tkIdx++

	// Ninth token should be "=>".
	if err := consumeToken("=>", tokens, lnIdx, tkIdx); err != nil {
		return nil, err
	}
	tkIdx++

	// Tenth token should be "reg".
	if err := consumeToken("reg", tokens, lnIdx, tkIdx); err != nil {
		return nil, err
	}
	tkIdx++

	// Eleventh token should be the uint8 representing the register index.
	reg, err := parseRegister(tokens[tkIdx], lnIdx, tkIdx)
	if err != nil {
		return nil, err
	}
	tkIdx++

	// Create the operation with the specified arguments.
	pdload, err := newPayloadLoad(base, offset, blen, reg)
	if err != nil {
		return nil, err
	}

	return pdload, nil
}

// InterpretPayloadSet creates a new PayloadSet operation from the given string.
func InterpretPayloadSet(line string, lnIdx int) (operation, *syserr.AnnotatedError) {
	tokens := strings.Fields(line)

	// Requires at least 19 tokens:
	// 		"[", "payload", "write", "reg", register index, "=>", len+"b", "@", payload base, "header", "+", offset,
	//		"csum_type", checksum type, "csum_off", checksum offset, "csum_flags", checksum flags as hexadecimal, "]".
	if len(tokens) != 19 {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("incorrect number of tokens for payload set operation, should be 19, got %d", len(tokens)))
	}

	if err := checkOperationBrackets(tokens, lnIdx); err != nil {
		return nil, err
	}

	tkIdx := 1

	// First token should be "payload".
	if err := consumeToken("payload", tokens, lnIdx, tkIdx); err != nil {
		return nil, err
	}
	tkIdx++

	// Second token should be "write".
	if err := consumeToken("write", tokens, lnIdx, tkIdx); err != nil {
		return nil, err
	}
	tkIdx++

	// Third token should be "reg"
	if err := consumeToken("reg", tokens, lnIdx, tkIdx); err != nil {
		return nil, err
	}
	tkIdx++

	// Fourth token should be the uint8 representing the register index.
	reg, err := parseRegister(tokens[tkIdx], lnIdx, tkIdx)
	if err != nil {
		return nil, err
	}
	tkIdx++

	// Fifth token should be "=>".
	if err := consumeToken("=>", tokens, lnIdx, tkIdx); err != nil {
		return nil, err
	}
	tkIdx++

	// Sixth token should be the length (in bytes) of the payload followed by 'b'.
	blen, err := parseUint8PlusChar(tokens[tkIdx], 'b', lnIdx, tkIdx)
	if err != nil {
		return nil, err
	}
	tkIdx++

	// Seventh token should be "@".
	if err := consumeToken("@", tokens, lnIdx, tkIdx); err != nil {
		return nil, err
	}
	tkIdx++

	// Eighth token should be the payload base header.
	base, err := parsePayloadBase(tokens[tkIdx], lnIdx, tkIdx)
	if err != nil {
		return nil, err
	}
	tkIdx++

	// Ninth token should be "header".
	if err := consumeToken("header", tokens, lnIdx, tkIdx); err != nil {
		return nil, err
	}
	tkIdx++

	// Tenth token should be "+".
	if err := consumeToken("+", tokens, lnIdx, tkIdx); err != nil {
		return nil, err
	}
	tkIdx++

	// Eleventh token should be the uint8 representing the offset.
	offset, err := parseUint8(tokens[tkIdx], "offset", lnIdx, tkIdx)
	if err != nil {
		return nil, err
	}
	tkIdx++

	// Twelfth token should be "csum_type".
	if err := consumeToken("csum_type", tokens, lnIdx, tkIdx); err != nil {
		return nil, err
	}
	tkIdx++

	// Thirteenth token should be the uint8 representing the checksum type.
	csumType, err := parseUint8(tokens[tkIdx], "checksum type", lnIdx, tkIdx)
	if err != nil {
		return nil, err
	}
	tkIdx++

	// Fourteenth token should be "csum_off".
	if err := consumeToken("csum_off", tokens, lnIdx, tkIdx); err != nil {
		return nil, err
	}
	tkIdx++

	// Fifteenth token should be the uint8 representing the checksum offset.
	csumOff, err := parseUint8(tokens[tkIdx], "checksum offset", lnIdx, tkIdx)
	if err != nil {
		return nil, err
	}
	tkIdx++

	// Sixteenth token should be "csum_flags".
	if err := consumeToken("csum_flags", tokens, lnIdx, tkIdx); err != nil {
		return nil, err
	}
	tkIdx++

	// Seventeenth token should be the uint8 representing checksum flags (in hex).
	csumFlags, err := parseUint8(tokens[tkIdx], "checksum flags", lnIdx, tkIdx)
	if err != nil {
		return nil, err
	}
	tkIdx++

	// Create the operation with the specified arguments.
	pdset, err := newPayloadSet(base, offset, blen, reg, csumType, csumOff, csumFlags)
	if err != nil {
		return nil, err
	}

	return pdset, nil
}

// InterpretBitwiseBool creates a new Comparison operation from the given string.
func InterpretBitwiseBool(line string, lnIdx int) (operation, *syserr.AnnotatedError) {
	tokens := strings.Fields(line)

	// Requires at least 14 tokens:
	// 		"[", "bitwise", "reg", dreg index, "=", "(", "reg", sreg index, "&", mask value, ")", "^", xor value, "]".
	if len(tokens) < 14 {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("incorrect number of tokens for bitwise operation, should be at least 14, got %d", len(tokens)))
	}

	if err := checkOperationBrackets(tokens, lnIdx); err != nil {
		return nil, err
	}

	tkIdx := 1

	// First token should be "bitwise".
	if err := consumeToken("bitwise", tokens, lnIdx, tkIdx); err != nil {
		return nil, err
	}
	tkIdx++

	// Second token should be "reg".
	if err := consumeToken("reg", tokens, lnIdx, tkIdx); err != nil {
		return nil, err
	}
	tkIdx++

	// Third token should be the uint8 representing destination register index.
	dreg, err := parseRegister(tokens[tkIdx], lnIdx, tkIdx)
	if err != nil {
		return nil, err
	}
	tkIdx++

	// Fourth token should be "=".
	if err := consumeToken("=", tokens, lnIdx, tkIdx); err != nil {
		return nil, err
	}
	tkIdx++

	// Fifth token should be "(".
	if err := consumeToken("(", tokens, lnIdx, tkIdx); err != nil {
		return nil, err
	}
	tkIdx++

	// Sixth token should be "reg".
	if err := consumeToken("reg", tokens, lnIdx, tkIdx); err != nil {
		return nil, err
	}
	tkIdx++

	// Seventh token should be the uint8 representing source register index.
	sreg, err := parseRegister(tokens[tkIdx], lnIdx, tkIdx)
	if err != nil {
		return nil, err
	}
	tkIdx++

	// Eighth token should be "&".
	if err := consumeToken("&", tokens, lnIdx, tkIdx); err != nil {
		return nil, err
	}
	tkIdx++

	// Ninth token should be the bytesData representing the mask value.
	nextIdx, mask, err := parseHexData(tokens, lnIdx, tkIdx)
	if err != nil {
		return nil, err
	}
	tkIdx = nextIdx

	// Tenth token should be ")".
	if err := consumeToken(")", tokens, lnIdx, tkIdx); err != nil {
		return nil, err
	}
	tkIdx++

	// Eleventh token should be "^".
	if err := consumeToken("^", tokens, lnIdx, tkIdx); err != nil {
		return nil, err
	}
	tkIdx++

	// Twelfth token should be the bytesData representing the xor value.
	nextIdx, xor, err := parseHexData(tokens, lnIdx, tkIdx)
	if err != nil {
		return nil, err
	}
	tkIdx = nextIdx

	// Done parsing tokens.
	if tkIdx != len(tokens)-1 {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "unexpected token after bitwise boolean operation")
	}

	// Create the operation with the specified arguments.
	bitwiseBool, err := newBitwiseBool(sreg, dreg, mask, xor)
	if err != nil {
		return nil, err
	}

	return bitwiseBool, nil
}

// InterpretCounter creates a new Counter operation from the given string.
func InterpretCounter(line string, lnIdx int) (operation, *syserr.AnnotatedError) {
	tokens := strings.Fields(line)

	// Requires exactly 7 tokens:
	// 		"[", "counter", "pkts", initial packets, "bytes", initial bytes, "]".
	if len(tokens) != 7 {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("incorrect number of tokens for counter operation, should be 7, got %d", len(tokens)))
	}

	if err := checkOperationBrackets(tokens, lnIdx); err != nil {
		return nil, err
	}

	tkIdx := 1

	// First token should be "counter".
	if err := consumeToken("counter", tokens, lnIdx, tkIdx); err != nil {
		return nil, err
	}
	tkIdx++

	// Second token should be "pkts".
	if err := consumeToken("pkts", tokens, lnIdx, tkIdx); err != nil {
		return nil, err
	}
	tkIdx++

	// Third token should be int64 representing initial packets.
	initialPkts, err := strconv.ParseUint(tokens[tkIdx], 10, 64)
	if err != nil {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("could not parse int64 initial packets: '%s'", tokens[tkIdx]))
	}
	tkIdx++

	// Fourth token should be "bytes".
	if err := consumeToken("bytes", tokens, lnIdx, tkIdx); err != nil {
		return nil, err
	}
	tkIdx++

	// Fifth token should be int64 representing initial bytes.
	initialBytes, err := strconv.ParseUint(tokens[tkIdx], 10, 64)
	if err != nil {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("could not parse int64 initial bytes: '%s'", tokens[tkIdx]))
	}
	tkIdx++

	// Create the operation with the specified arguments.
	cntr := newCounter(initialPkts, initialBytes)

	return cntr, nil
}

// InterpretRoute creates a new Route operation from the given string.
func InterpretRoute(line string, lnIdx int) (operation, *syserr.AnnotatedError) {
	tokens := strings.Fields(line)

	// Requires exactly 8 tokens:
	// 		"[", "rt", "load", route key, "=>", "reg", register index, "]".
	if len(tokens) != 8 {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("incorrect number of tokens for route operation, should be 8, got %d", len(tokens)))
	}

	if err := checkOperationBrackets(tokens, lnIdx); err != nil {
		return nil, err
	}

	tkIdx := 1

	// First token should be "rt".
	if err := consumeToken("rt", tokens, lnIdx, tkIdx); err != nil {
		return nil, err
	}
	tkIdx++

	// Second token should be "load".
	if err := consumeToken("load", tokens, lnIdx, tkIdx); err != nil {
		return nil, err
	}
	tkIdx++

	// Third token should be the route key.
	key, err := parseRouteKey(tokens[tkIdx], lnIdx, tkIdx)
	if err != nil {
		return nil, err
	}
	tkIdx++

	// Fourth token should be "=>".
	if err := consumeToken("=>", tokens, lnIdx, tkIdx); err != nil {
		return nil, err
	}
	tkIdx++

	// Fifth token should be "reg".
	if err := consumeToken("reg", tokens, lnIdx, tkIdx); err != nil {
		return nil, err
	}
	tkIdx++

	// Sixth token should be the uint8 representing the register index.
	reg, err := parseRegister(tokens[tkIdx], lnIdx, tkIdx)
	if err != nil {
		return nil, err
	}
	tkIdx++

	// Create the operation with the specified arguments.
	rt, err := newRoute(key, reg)
	if err != nil {
		return nil, err
	}

	return rt, nil
}

// InterpretByteorder creates a new Byteorder operation from the given string.
func InterpretByteorder(line string, lnIdx int) (operation, *syserr.AnnotatedError) {
	tokens := strings.Fields(line)

	// Requires exactly 10 tokens:
	// 		"[", "byteorder", "reg", dreg index, "=", byteorder op+"(reg", sreg index+",", size+",", blen+")", "]".
	if len(tokens) != 10 {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("incorrect number of tokens for byteorder operation, should be 10, got %d", len(tokens)))
	}

	if err := checkOperationBrackets(tokens, lnIdx); err != nil {
		return nil, err
	}

	tkIdx := 1

	// First token should be "byteorder".
	if err := consumeToken("byteorder", tokens, lnIdx, tkIdx); err != nil {
		return nil, err
	}
	tkIdx++

	// Second token should be "reg".
	if err := consumeToken("reg", tokens, lnIdx, tkIdx); err != nil {
		return nil, err
	}
	tkIdx++

	// Third token should be the uint8 representing destination register index.
	dreg, err := parseRegister(tokens[tkIdx], lnIdx, tkIdx)
	if err != nil {
		return nil, err
	}
	tkIdx++

	// Fourth token should be "=".
	if err := consumeToken("=", tokens, lnIdx, tkIdx); err != nil {
		return nil, err
	}
	tkIdx++

	// Fifth token should be "ntoh(reg".
	var bop byteorderOp
	switch tokens[tkIdx] {
	case "ntoh(reg":
		bop = linux.NFT_BYTEORDER_NTOH
	case "hton(reg":
		bop = linux.NFT_BYTEORDER_HTON
	default:
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("expected 'ntoh' or 'hton' keyword followed by '(reg' at token %d, got '%s'", tkIdx, tokens[tkIdx]))
	}
	tkIdx++

	// Sixth token should be the source register index followed by ','.
	sreg, err := parseUint8PlusChar(tokens[tkIdx], ',', lnIdx, tkIdx)
	if err != nil {
		return nil, err
	}
	tkIdx++

	// Seventh token should be the size in bytes followed by ','.
	size, err := parseUint8PlusChar(tokens[tkIdx], ',', lnIdx, tkIdx)
	if err != nil {
		return nil, err
	}
	tkIdx++

	// Eighth token should be the length in bytes followed by ')'.
	blen, err := parseUint8PlusChar(tokens[tkIdx], ')', lnIdx, tkIdx)
	if err != nil {
		return nil, err
	}
	tkIdx++

	// Create the operation with the specified arguments.
	order, err := newByteorder(dreg, sreg, bop, blen, size)
	if err != nil {
		return nil, err
	}

	return order, nil
}

// InterpretMetaLoad creates a new MetaLoad operation from the given string.
func InterpretMetaLoad(line string, lnIdx int) (operation, *syserr.AnnotatedError) {
	tokens := strings.Fields(line)

	// Requires exactly 8 tokens:
	// 		"[", "meta", "load", meta key, "=>", "reg", register index, "]".
	if len(tokens) != 8 {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("incorrect number of tokens for meta load operation, should be 8, got %d", len(tokens)))
	}

	if err := checkOperationBrackets(tokens, lnIdx); err != nil {
		return nil, err
	}

	tkIdx := 1

	// First token should be "meta".
	if err := consumeToken("meta", tokens, lnIdx, tkIdx); err != nil {
		return nil, err
	}
	tkIdx++

	// Second token should be "load".
	if err := consumeToken("load", tokens, lnIdx, tkIdx); err != nil {
		return nil, err
	}
	tkIdx++

	// Third token should be the meta key.
	key, err := parseMetaKey(tokens[tkIdx], lnIdx, tkIdx)
	if err != nil {
		return nil, err
	}
	tkIdx++

	// Fourth token should be "=>".
	if err := consumeToken("=>", tokens, lnIdx, tkIdx); err != nil {
		return nil, err
	}
	tkIdx++

	// Fifth token should be "reg".
	if err := consumeToken("reg", tokens, lnIdx, tkIdx); err != nil {
		return nil, err
	}
	tkIdx++

	// Sixth token should be the uint8 representing the register index.
	reg, err := parseRegister(tokens[tkIdx], lnIdx, tkIdx)
	if err != nil {
		return nil, err
	}
	tkIdx++

	// Create the operation with the specified arguments.
	mtLoad, err := newMetaLoad(key, reg)
	if err != nil {
		return nil, err
	}

	return mtLoad, nil
}

// InterpretMetaSet creates a new MetaSet operation from the given string.
func InterpretMetaSet(line string, lnIdx int) (operation, *syserr.AnnotatedError) {
	tokens := strings.Fields(line)

	// Requires exactly 8 tokens:
	// 		"[", "meta", "set", meta key, "with", "reg", register index, "]".
	if len(tokens) != 8 {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("incorrect number of tokens for meta set operation, should be 8, got %d", len(tokens)))
	}

	if err := checkOperationBrackets(tokens, lnIdx); err != nil {
		return nil, err
	}

	tkIdx := 1

	// First token should be "meta".
	if err := consumeToken("meta", tokens, lnIdx, tkIdx); err != nil {
		return nil, err
	}
	tkIdx++

	// Second token should be "set".
	if err := consumeToken("set", tokens, lnIdx, tkIdx); err != nil {
		return nil, err
	}
	tkIdx++

	// Third token should be the meta key.
	key, err := parseMetaKey(tokens[tkIdx], lnIdx, tkIdx)
	if err != nil {
		return nil, err
	}
	tkIdx++

	// Fourth token should be "with".
	if err := consumeToken("with", tokens, lnIdx, tkIdx); err != nil {
		return nil, err
	}
	tkIdx++

	// Fifth token should be "reg".
	if err := consumeToken("reg", tokens, lnIdx, tkIdx); err != nil {
		return nil, err
	}
	tkIdx++

	// Sixth token should be the uint8 representing the register index.
	reg, err := parseRegister(tokens[tkIdx], lnIdx, tkIdx)
	if err != nil {
		return nil, err
	}
	tkIdx++

	// Create the operation with the specified arguments.
	mtSet, err := newMetaSet(key, reg)
	if err != nil {
		return nil, err
	}

	return mtSet, nil
}

//
// Interpreter Helper Functions.
//

// checkOperationBrackets checks that the operation string is surrounded by
// square brackets.
func checkOperationBrackets(tokens []string, lnIdx int) *syserr.AnnotatedError {
	if tokens[0] != "[" {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("expected operation to be surrounded by '[]', got '%s'", tokens[0]))
	}
	if tokens[len(tokens)-1] != "]" {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "operation missing closing square bracket")
	}
	return nil
}

// parseUint8 parses the uint8 which should be supposed from the given string.
// Input starting with "0x" are parsed as base 16, otherwise assumes base 10.
func parseUint8(regString string, supposed string, lnIdx int, tkIdx int) (uint8, *syserr.AnnotatedError) {
	var v64 uint64
	var err error
	if len(regString) > 2 && regString[:2] == "0x" {
		v64, err = strconv.ParseUint(regString[2:], 16, 8)
	} else {
		v64, err = strconv.ParseUint(regString, 10, 8)
	}
	if err != nil {
		return 0, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("could not parse uint8 %s: '%s'", supposed, regString))
	}
	return uint8(v64), nil
}

// parseRegister parses the register index from the given string.
func parseRegister(regString string, lnIdx int, tkIdx int) (uint8, *syserr.AnnotatedError) {
	reg, err := parseUint8(regString, "register index", lnIdx, tkIdx)
	if err != nil {
		return 0, err
	}
	if !isRegister(reg) {
		return 0, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("register index %d is not a valid register index", reg))
	}
	return reg, nil
}

// parseRegisterData parses the register data from the given token and returns
// the index of the next token to process (can consume multiple tokens).
// Note: assumes the register index is valid (was checked in parseRegister).
func parseRegisterData(reg uint8, tokens []string, lnIdx int, tkIdx int) (int, registerData, *syserr.AnnotatedError) {
	// Handles verdict data.
	if isVerdictRegister(reg) {
		nextIdx, verdict, err := parseVerdict(tokens, lnIdx, tkIdx)
		if err != nil {
			return 0, nil, err
		}
		return nextIdx, newVerdictData(verdict), nil
	}
	// Handles hex data.
	if len(tokens[tkIdx]) > 1 && tokens[tkIdx][:2] == "0x" {
		nextIdx, data, err := parseHexData(tokens, lnIdx, tkIdx)
		if err != nil {
			return 0, nil, err
		}
		bytesData := newBytesData(data)
		if err := bytesData.validateRegister(reg); err != nil {
			return 0, nil, err
		}
		return nextIdx, bytesData, nil
	}
	// TODO(b/345684870): cases will be added here as more types are supported.
	return 0, nil, syserr.NewAnnotatedError(syserr.ErrNotSupported, fmt.Sprintf("unsupported register data type for register %d", reg))
}

// verdictCodeFromKeyword is a map of verdict keyword to its corresponding enum value.
var verdictCodeFromKeyword = map[string]int32{
	"accept":   linux.NF_ACCEPT,
	"drop":     linux.NF_DROP,
	"continue": linux.NFT_CONTINUE,
	"return":   linux.NFT_RETURN,
	"jump":     linux.NFT_JUMP,
	"goto":     linux.NFT_GOTO,
}

// parseVerdict parses the verdict from the given token and returns
// the index of the next token to process (can consume multiple tokens).
func parseVerdict(tokens []string, lnIdx int, tkIdx int) (int, stack.NFVerdict, *syserr.AnnotatedError) {
	v := stack.NFVerdict{}

	vcString := tokens[tkIdx]
	vc, ok := verdictCodeFromKeyword[vcString]
	if !ok {
		return 0, v, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("unknown verdict code: %s", vcString))
	}
	v.Code = VC(vc)
	tkIdx++

	// jump and chain verdicts require 2 more tokens to specify the target chain.
	//		"jump"/"goto", "->", chain name.
	switch v.Code {
	case VC(linux.NFT_JUMP), VC(linux.NFT_GOTO):
		if err := consumeToken("->", tokens, lnIdx, tkIdx); err != nil {
			return 0, v, err
		}
		tkIdx++

		if err := validateIdentifier(tokens[tkIdx], lnIdx, tkIdx); err != nil {
			return 0, v, err
		}
		v.ChainName = tokens[tkIdx]
		tkIdx++
	}

	return tkIdx, v, nil
}

// parseHexData parses little endian hexadecimal data from the given token,
// converts to big endian, and returns the index of the next token to process.
func parseHexData(tokens []string, lnIdx int, tkIdx int) (int, []byte, *syserr.AnnotatedError) {
	var bytes []byte
	for ; tkIdx < len(tokens); tkIdx++ {
		if len(tokens[tkIdx]) <= 2 || tokens[tkIdx][:2] != "0x" {
			break
		}

		// Hexadecimal data must have 2 digits per byte (even number of characters).
		if len(tokens[tkIdx])%2 != 0 {
			return 0, nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("invalid hexadecimal data: '%s'", tokens[tkIdx]))
		}

		// Decodes the little endian hex string into bytes
		bytes4, err := hex.DecodeString(tokens[tkIdx][2:])
		if err != nil {
			return 0, nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("could not decode hexadecimal data: '%s'", tokens[tkIdx]))
		}
		// Converts the bytes to big endian and appends to the bytes slice.
		slices.Reverse(bytes4)
		bytes = append(bytes, bytes4...)
	}
	if len(bytes) > linux.NFT_REG_SIZE {
		return 0, nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("cannot have more than %d bytes of hexadecimal data, got %d", linux.NFT_REG_SIZE, len(bytes)))
	}
	return tkIdx, bytes, nil
}

// cmpOpFromKeyword is a map of comparison operator keywords to their
// corresponding enum value.
var cmpOpFromKeyword = map[string]int{
	"eq":  linux.NFT_CMP_EQ,
	"neq": linux.NFT_CMP_NEQ,
	"lt":  linux.NFT_CMP_LT,
	"lte": linux.NFT_CMP_LTE,
	"gt":  linux.NFT_CMP_GT,
	"gte": linux.NFT_CMP_GTE,
}

// parseCmpOp parses the int representing the cmpOp from the given string.
func parseCmpOp(copString string, lnIdx int, tkIdx int) (int, *syserr.AnnotatedError) {
	cop, ok := cmpOpFromKeyword[copString]
	if !ok {
		return 0, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("unknown cmp operator keyword: %s", copString))
	}
	return cop, nil
}

// parseUint8PlusChar parses the a uint8 followed by the given character from
// the given string.
func parseUint8PlusChar(numString string, char byte, lnIdx int, tkIdx int) (uint8, *syserr.AnnotatedError) {
	lastChar := numString[len(numString)-1]
	if lastChar != char {
		return 0, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("expected character '%c' at the end of the string, got '%c'", char, lastChar))
	}
	numStr := numString[:len(numString)-1]
	num, err := strconv.ParseUint(numStr, 10, 8)
	if err != nil {
		return 0, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("could not parse uint8 %s: '%s'", numString, numStr))
	}
	return uint8(num), nil
}

// payloadBaseFromKeyword is a map of payload base keywords to their
// corresponding enum value.
var payloadBaseFromKeyword = map[string]payloadBase{
	"link":      linux.NFT_PAYLOAD_LL_HEADER,
	"network":   linux.NFT_PAYLOAD_NETWORK_HEADER,
	"transport": linux.NFT_PAYLOAD_TRANSPORT_HEADER,
}

// parsePayloadBase parses the payload base header from the given string.
func parsePayloadBase(baseString string, lnIdx int, tkIdx int) (payloadBase, *syserr.AnnotatedError) {
	base, ok := payloadBaseFromKeyword[baseString]
	if !ok {
		// Inner and Tunnel Headers cannot be specified in payload load operation.
		return 0, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("unknown payload base keyword: %s", baseString))
	}
	return base, nil
}

// routeKeys is a map of route key keywords to their corresponding enum value.
var routeKeyFromKeyword = map[string]routeKey{
	// Fully supported route keys.
	"nexthop4": linux.NFT_RT_NEXTHOP4,
	"nexthop6": linux.NFT_RT_NEXTHOP6,
	"tcpmss":   linux.NFT_RT_TCPMSS,
	// Keys supported for interpretation but not yet for logic/evaluation.
	// Note: Will result in logic error during operation construction.
	"classid": linux.NFT_RT_CLASSID,
	"ipsec":   linux.NFT_RT_XFRM,
}

// parseRouteKey parses the route key from the given string.
func parseRouteKey(keyString string, lnIdx int, tkIdx int) (routeKey, *syserr.AnnotatedError) {
	key, ok := routeKeyFromKeyword[keyString]
	if !ok {
		return 0, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("unknown route key keyword: %s", keyString))
	}
	return key, nil
}

// metaKeyFromKeyword is a map of meta key keywords to their corresponding enum value.
var metaKeyFromKeyword = map[string]metaKey{
	// Supported meta keys.
	"len":       linux.NFT_META_LEN,
	"protocol":  linux.NFT_META_PROTOCOL,
	"nfproto":   linux.NFT_META_NFPROTO,
	"l4proto":   linux.NFT_META_L4PROTO,
	"skuid":     linux.NFT_META_SKUID,
	"skgid":     linux.NFT_META_SKGID,
	"rtclassid": linux.NFT_META_RTCLASSID,
	"pkttype":   linux.NFT_META_PKTTYPE,
	"prandom":   linux.NFT_META_PRANDOM,
	"time":      linux.NFT_META_TIME_NS,
	"day":       linux.NFT_META_TIME_DAY,
	"hour":      linux.NFT_META_TIME_HOUR,
	// Unsupported meta keys.
	"priority": linux.NFT_META_PRIORITY,
	"mark":     linux.NFT_META_MARK,
	"iif":      linux.NFT_META_IIF,
	"oif":      linux.NFT_META_OIF,
	"iifname":  linux.NFT_META_IIFNAME,
	"oifname":  linux.NFT_META_OIFNAME,
	"iiftype":  linux.NFT_META_IIFTYPE,
	"oiftype":  linux.NFT_META_OIFTYPE,
	"iifgroup": linux.NFT_META_IIFGROUP,
	"oifgroup": linux.NFT_META_OIFGROUP,
	"cgroup":   linux.NFT_META_CGROUP,
	"iifkind":  linux.NFT_META_IIFKIND,
	"oifkind":  linux.NFT_META_OIFKIND,
	"sdif":     linux.NFT_META_SDIF,
	"sdifname": linux.NFT_META_SDIFNAME,
	"nftrace":  linux.NFT_META_NFTRACE,
	"cpu":      linux.NFT_META_CPU,
	"secmark":  linux.NFT_META_SECMARK,
	"secpath":  linux.NFT_META_SECPATH,
	"broute":   linux.NFT_META_BRI_BROUTE,
}

// parseMetaKey parses the meta key from the given string.
func parseMetaKey(keyString string, lnIdx int, tkIdx int) (metaKey, *syserr.AnnotatedError) {
	key, ok := metaKeyFromKeyword[keyString]
	if !ok {
		return 0, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("unknown meta key keyword: %s", keyString))
	}
	return key, nil
}

// consumeToken is a helper function that checks if the token at the given index
// matches the expected string, returning a SyntaxError if not.
func consumeToken(expected string, tokens []string, lnIdx int, tkIdx int) *syserr.AnnotatedError {
	if tokens[tkIdx] != expected {
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("unexpected string: %s", tokens[tkIdx]))
	}
	return nil
}
