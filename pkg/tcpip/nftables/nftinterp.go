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
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"gvisor.dev/gvisor/pkg/abi/linux"
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
func validateIdentifier(id string, lnIdx int, tkIdx int) error {
	if _, ok := reservedKeywordSet[id]; ok {
		return &SyntaxError{lnIdx, tkIdx, fmt.Sprintf("cannot use reserved keyword %s as an identifier", id)}
	}

	if !identifierRegexp.MatchString(id) {
		return &SyntaxError{lnIdx, tkIdx, fmt.Sprintf("invalid identifier %s", id)}
	}

	return nil
}

// InterpretRule creates a new Rule from the given rule string, assumed to be
// represented as a block of text with a single operation per line.
// Note: the rule string should be generated as output from the official nft
// binary (can be accomplished by using flag --debug=netlink).
func InterpretRule(ruleString string) (*Rule, error) {
	ruleString = strings.TrimSpace(ruleString)
	lines := slices.DeleteFunc(strings.Split(ruleString, "\n"), func(s string) bool {
		return s == ""
	})

	r := &Rule{ops: make([]Operation, 0, len(lines))}

	// Interprets all operations in the rule.
	for lnIdx, line := range lines {
		op, err := InterpretOperation(line, lnIdx)
		if err != nil {
			return nil, err
		}
		if err := r.AddOperation(op); err != nil {
			return nil, err
		}
	}

	return r, nil
}

// InterpretOperation creates a new Operation from the given operation string,
// assumed to be a single line of text surrounded in square brackets.
// Note: the operation string should be generated as output from the official nft
// binary (can be accomplished by using flag --debug=netlink).
func InterpretOperation(line string, lnIdx int) (Operation, error) {
	tokens := strings.Fields(line)
	if len(tokens) < 2 {
		return nil, &SyntaxError{lnIdx, 0, fmt.Sprintf("incorrect number of tokens for operation, should be at least 2, got %d", len(tokens))}
	}

	// Second token decides the operation type.
	switch tokens[1] {
	case "immediate":
		return InterpretImmediate(line, lnIdx)
	case "cmp":
		return InterpretComparison(line, lnIdx)
	default:
		return nil, &SyntaxError{lnIdx, 1, fmt.Sprintf("unrecognized operation type: %s", tokens[1])}
	}
}

// InterpretImmediate creates a new Immediate operation from the given string.
func InterpretImmediate(line string, lnIdx int) (Operation, error) {
	tokens := strings.Fields(line)

	// Requires at least 6 tokens:
	// 		"[", "immediate", "reg", register index, register value, "]".
	if len(tokens) < 6 {
		return nil, &SyntaxError{lnIdx, 0, fmt.Sprintf("incorrect number of tokens for immediate operation, should be at least 6, got %d", len(tokens))}
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
		return nil, &SyntaxError{lnIdx, tkIdx, "unexpected token after immediate operation"}
	}

	// Create the operation with the specified arguments.
	imm, err := NewImmediate(reg, data)
	if err != nil {
		return nil, &LogicError{lnIdx, tkIdx, err}
	}

	return imm, nil
}

// InterpretComparison creates a new Comparison operation from the given string.
func InterpretComparison(line string, lnIdx int) (Operation, error) {
	tokens := strings.Fields(line)

	// Requires at least 7 tokens:
	// 		"[", "cmp", op, "reg", register index, register value, "]".
	if len(tokens) < 7 {
		return nil, &SyntaxError{lnIdx, 0, fmt.Sprintf("incorrect number of tokens for cmp operation, should be at least 7, got %d", len(tokens))}
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

	// Fifth token should be the value.
	nextIdx, data, err := parseRegisterData(reg, tokens, lnIdx, tkIdx)
	if err != nil {
		return nil, err
	}
	tkIdx = nextIdx

	// Done parsing tokens.
	if tkIdx != len(tokens)-1 {
		return nil, &SyntaxError{lnIdx, tkIdx, "unexpected token after comparison operation"}
	}

	// Create the operation with the specified arguments.
	cmp, err := NewComparison(reg, cop, data)
	if err != nil {
		return nil, &LogicError{lnIdx, tkIdx, err}
	}

	return cmp, nil
}

//
// Interpreter Helper Functions.
//

// checkOperationBrackets checks that the operation string is surrounded by
// square brackets.
func checkOperationBrackets(tokens []string, lnIdx int) error {
	if tokens[0] != "[" {
		return &SyntaxError{lnIdx, 0, "operation missing opening square bracket"}
	}
	if tokens[len(tokens)-1] != "]" {
		return &SyntaxError{lnIdx, len(tokens) - 1, "operation missing closing square bracket"}
	}
	return nil
}

// parseRegister parses the register index from the given string.
func parseRegister(regString string, lnIdx int, tkIdx int) (uint8, error) {
	reg64, err := strconv.ParseUint(regString, 10, 8)
	if err != nil {
		return 0, &SyntaxError{lnIdx, tkIdx, fmt.Sprintf("could not parse uint8 register index: '%s'", regString)}
	}

	if reg64 > math.MaxUint8 || !isRegister(uint8(reg64)) {
		return 0, &SyntaxError{lnIdx, tkIdx, fmt.Sprintf("invalid register index: %d", reg64)}
	}

	return uint8(reg64), nil
}

// parseRegisterData parses the register data from the given token and returns
// the index of the next token to process (can consume multiple tokens).
// Note: assumes the register index is valid (was checked in parseRegister).
func parseRegisterData(reg uint8, tokens []string, lnIdx int, tkIdx int) (int, RegisterData, error) {
	// Handles verdict data.
	if isVerdictRegister(reg) {
		nextIdx, verdict, err := parseVerdict(tokens, lnIdx, tkIdx)
		if err != nil {
			return 0, nil, err
		}
		return nextIdx, NewVerdictData(verdict), nil
	}
	// Handles hex data (4-, 8-, 12-, or 16-byte).
	if len(tokens[tkIdx]) > 1 && tokens[tkIdx][:2] == "0x" {
		nextIdx, data, err := parseHexData(tokens, lnIdx, tkIdx)
		if err != nil {
			return 0, nil, err
		}
		// 4-byte data is only valid for 4-byte register. Any byte data can be
		// stored in 16-byte registerValidates the register data type.
		if err := data.ValidateRegister(reg); err != nil {
			return 0, nil, &LogicError{lnIdx, tkIdx, err}
		}
		return nextIdx, data, nil
	}
	// TODO(b/345684870): cases will be added here as more types are supported.
	return 0, nil, &SyntaxError{lnIdx, tkIdx, fmt.Sprintf("invalid register data: '%s'", tokens[tkIdx])}
}

// parseVerdict parses the verdict from the given token and returns
// the index of the next token to process (can consume multiple tokens).
func parseVerdict(tokens []string, lnIdx int, tkIdx int) (int, Verdict, error) {
	v := Verdict{}

	switch tokens[tkIdx] {
	case "accept":
		v.Code = VC(linux.NF_ACCEPT)
	case "drop":
		v.Code = VC(linux.NF_DROP)
	case "continue":
		v.Code = VC(linux.NFT_CONTINUE)
	case "return":
		v.Code = VC(linux.NFT_RETURN)
	case "jump":
		v.Code = VC(linux.NFT_JUMP)
	case "goto":
		v.Code = VC(linux.NFT_GOTO)
	default:
		return 0, v, &SyntaxError{lnIdx, tkIdx, fmt.Sprintf("invalid verdict: '%s'", tokens[tkIdx])}
	}
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

// parseHexData parses little endian hexadecimal data from the given token and
// returns the index of the next token to process (can consume multiple tokens).
func parseHexData(tokens []string, lnIdx int, tkIdx int) (int, RegisterData, error) {
	var bytes []byte
	for ; tkIdx < len(tokens); tkIdx++ {
		if len(tokens[tkIdx]) < 2 || tokens[tkIdx][:2] != "0x" {
			break
		}

		if len(tokens[tkIdx]) != 10 {
			return 0, nil, &SyntaxError{lnIdx, tkIdx, fmt.Sprintf("hexadecimal data must be exactly 8 digits long (excluding 0x): '%s'", tokens[tkIdx])}
		}

		// Decodes the little endian hex string into bytes
		bytes4, err := hex.DecodeString(tokens[tkIdx][2:])
		if err != nil {
			return 0, nil, &SyntaxError{lnIdx, tkIdx, fmt.Sprintf("could not decode hexadecimal data: '%s'", tokens[tkIdx])}
		}
		bytes = append(bytes, bytes4...)
	}
	if len(bytes) > 16 {
		return 0, nil, &SyntaxError{lnIdx, tkIdx, fmt.Sprintf("cannot have more than 16 bytes of hexadecimal data, got %d", len(bytes))}
	}
	return tkIdx, NewBytesData(bytes), nil
}

// parseCmpOp parses the NftCmpOp from the given string.
func parseCmpOp(copString string, lnIdx int, tkIdx int) (NftCmpOp, error) {
	switch copString {
	case "eq":
		return linux.NFT_CMP_EQ, nil
	case "neq":
		return linux.NFT_CMP_NEQ, nil
	case "lt":
		return linux.NFT_CMP_LT, nil
	case "lte":
		return linux.NFT_CMP_LTE, nil
	case "gt":
		return linux.NFT_CMP_GT, nil
	case "gte":
		return linux.NFT_CMP_GTE, nil
	default:
		return 0, &SyntaxError{lnIdx, tkIdx, fmt.Sprintf("invalid comparison operator: '%s'", copString)}
	}
}

// consumeToken is a helper function that checks if the token at the given index
// matches the expected string, returning a SyntaxError if not.
func consumeToken(expected string, tokens []string, lnIdx int, tkIdx int) error {
	if tokens[tkIdx] != expected {
		return &SyntaxError{lnIdx, tkIdx, fmt.Sprintf("unexpected string: %s", tokens[tkIdx])}
	}
	return nil
}
