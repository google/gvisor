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
	"fmt"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type interpretOperationTestAction struct {
	tname    string
	opStr    string
	expected operation // will be nil if an error is expected
}

// checkOp is a generic operation validation function used for testing that
// the interpretation of an operation matches the expected operation.
func checkOp(t *testing.T, test interpretOperationTestAction, checkFunc func(string, operation, operation) error) {
	rule, err := InterpretRule(test.opStr)
	if test.expected == nil {
		if err == nil {
			t.Fatalf("unexpected interpretation success for %s", test.tname)
		}
		return
	}
	if err != nil {
		t.Fatalf("unexpected interpretation error for %s: %v", test.tname, err)
	}
	if len(rule.ops) != 1 {
		t.Fatalf("expected single operation for %s, got %d", test.tname, len(rule.ops))
	}
	actual := rule.ops[0]
	if actual == nil {
		t.Fatalf("expected non-nil operation for %s, got nil", test.tname)
	}
	if err := checkFunc(test.tname, test.expected, actual); err != nil {
		t.Fatalf("%s", err.Error())
	}
}

// TestInterpretImmediateOps tests interpretation of immediate operations.
func TestInterpretImmediateOps(t *testing.T) {
	for _, test := range []interpretOperationTestAction{
		{
			tname:    "verdict register with accept verdict",
			opStr:    "[ immediate reg 0 accept ]",
			expected: mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NF_ACCEPT)})),
		},
		{
			tname:    "verdict register with drop verdict",
			opStr:    "[ immediate reg 0 drop ]",
			expected: mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NF_DROP)})),
		},
		{
			tname:    "verdict register with continue verdict",
			opStr:    "[ immediate reg 0 continue ]",
			expected: mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_CONTINUE)})),
		},
		{
			tname:    "verdict register with return verdict",
			opStr:    "[ immediate reg 0 return ]",
			expected: mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_RETURN)})),
		},
		{
			tname:    "verdict register with jump verdict",
			opStr:    "[ immediate reg 0 jump -> next_chain ]",
			expected: mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_JUMP), ChainName: "next_chain"})),
		},
		{
			tname:    "verdict register with goto verdict",
			opStr:    "[ immediate reg 0 goto -> next_chain ]",
			expected: mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(stack.NFVerdict{Code: VC(linux.NFT_GOTO), ChainName: "next_chain"})),
		},
		{
			tname:    "verdict register with 4-byte data",
			opStr:    "[ immediate reg 0 0x0201a8c0 ]",
			expected: nil,
		},
		{
			tname:    "verdict register with 16-byte data",
			opStr:    "[ immediate reg 0 0xb80d0120 0x00000000 0x00000000 0x02000000 ]",
			expected: nil,
		},
		{
			tname:    "16-byte register with verdict data",
			opStr:    "[ immediate reg 1 accept ]",
			expected: nil,
		},
		{
			tname:    "16-byte register with verdict data with target",
			opStr:    "[ immediate reg 2 jump -> next_chain ]",
			expected: nil,
		},
		{
			tname:    "16-byte register with 4-byte data",
			opStr:    "[ immediate reg 1 0x0201a8c0 ]",
			expected: mustCreateImmediate(t, linux.NFT_REG_1, newBytesData([]byte{0xc0, 0xa8, 0x01, 0x02})),
		},
		{
			tname:    "16-byte register with 8-byte data",
			opStr:    "[ immediate reg 2 0xb80d0120 0x00000050 ]",
			expected: mustCreateImmediate(t, linux.NFT_REG_2, newBytesData([]byte{0x20, 0x01, 0x0d, 0xb8, 0x50, 0x00, 0x00, 0x00})),
		},
		{
			tname:    "16-byte register with 12-byte data",
			opStr:    "[ immediate reg 3 0xb80d0120 0x00000050 0xb80d0120 ]",
			expected: mustCreateImmediate(t, linux.NFT_REG_3, newBytesData([]byte{0x20, 0x01, 0x0d, 0xb8, 0x50, 0x00, 0x00, 0x00, 0x20, 0x01, 0x0d, 0xb8})),
		},
		{
			tname:    "16-byte register with 16-byte data",
			opStr:    "[ immediate reg 4 0xb80d0120 0x00000000 0x00000000 0x02000000 ]",
			expected: mustCreateImmediate(t, linux.NFT_REG_4, newBytesData([]byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02})),
		},
		{
			tname:    "4-byte register with verdict data",
			opStr:    "[ immediate reg 8 return ]",
			expected: nil,
		},
		{
			tname:    "4-byte register with verdict data with target",
			opStr:    "[ immediate reg 9 goto -> next_chain ]",
			expected: nil,
		},
		{
			tname:    "4-byte register with 16-byte data",
			opStr:    "[ immediate reg 9 0xb80d0120 0x00000000 0x00000000 0x02000000 ]",
			expected: nil,
		},
	} {
		t.Run(test.tname, func(t *testing.T) { checkOp(t, test, checkImmediateOp) })
	}
}

// checkImmediateOp checks that the given operation is an immediate operation
// and that it matches the expected immediate operation.
func checkImmediateOp(tname string, expected operation, actual operation) error {
	expectedImm := expected.(*immediate)
	imm, ok := actual.(*immediate)
	if !ok {
		return fmt.Errorf("expected operation type to be Immediate for %s, got %T", tname, actual)
	}
	if imm.dreg != expectedImm.dreg {
		return fmt.Errorf("expected register to be %d for %s, got %d", expectedImm.dreg, tname, imm.dreg)
	}
	if !imm.data.equal(expectedImm.data) {
		return fmt.Errorf("expected data to be %v for %s, got %v", expectedImm.data, tname, imm.data)
	}
	return nil
}

// TestInterpretComparisonOps tests interpretation of comparison operations.
func TestInterpretComparisonOps(t *testing.T) {
	for _, test := range []interpretOperationTestAction{
		{
			tname:    "verdict register with 4-byte data comparison",
			opStr:    "[ cmp eq reg 0 0x00000002 ]",
			expected: nil,
		},
		{
			tname:    "verdict register with 8-byte data comparison",
			opStr:    "[ cmp lt reg 0 0xb80d0120 0x02000000 ]",
			expected: nil,
		},
		{
			tname:    "verdict register with 12-byte data comparison",
			opStr:    "[ cmp gte reg 0 0xb80d0120 0x18305290 0x02000000 ]",
			expected: nil,
		},
		{
			tname:    "verdict register with 16-byte data comparison",
			opStr:    "[ cmp neq reg 0 0xb80d0120 0x18305290 0x18305290 0x02000000 ]",
			expected: nil,
		},
		{
			tname:    "4-byte register == 4-byte data",
			opStr:    "[ cmp eq reg 8 0x0302010a ]",
			expected: mustCreateComparison(t, linux.NFT_REG32_00, linux.NFT_CMP_EQ, []byte{0x0a, 0x01, 0x02, 0x03}),
		},
		{
			tname:    "4-byte register != 4-byte data",
			opStr:    "[ cmp neq reg 9 0x00000064 ]",
			expected: mustCreateComparison(t, linux.NFT_REG32_01, linux.NFT_CMP_NEQ, []byte{0x64, 0x00, 0x00, 0x00}),
		},
		{
			tname:    "4-byte register < 4-byte data",
			opStr:    "[ cmp lt reg 10 0x00000000 ]",
			expected: mustCreateComparison(t, linux.NFT_REG32_02, linux.NFT_CMP_LT, []byte{0x00, 0x00, 0x00, 0x00}),
		},
		{
			tname:    "4-byte register <= 4-byte data",
			opStr:    "[ cmp lte reg 11 0x00000164 ]",
			expected: mustCreateComparison(t, linux.NFT_REG32_03, linux.NFT_CMP_LTE, []byte{0x64, 0x01, 0x00, 0x00}),
		},
		{
			tname:    "4-byte register > 4-byte data",
			opStr:    "[ cmp gt reg 12 0xe8030000 ]",
			expected: mustCreateComparison(t, linux.NFT_REG32_04, linux.NFT_CMP_GT, []byte{0x00, 0x00, 0x03, 0xe8}),
		},
		{
			tname:    "4-byte register >= 4-byte data",
			opStr:    "[ cmp gte reg 13 0xc02b0000 ]",
			expected: mustCreateComparison(t, linux.NFT_REG32_05, linux.NFT_CMP_GTE, []byte{0x00, 0x00, 0x2b, 0xc0}),
		},
		{
			tname:    "4-byte register with 8-byte data comparison",
			opStr:    "[ cmp eq reg 14 0xb80d0120 0x02000000 ]",
			expected: nil,
		},
		{
			tname:    "4-byte register with 12-byte data comparison",
			opStr:    "[ cmp lte reg 15 0xb80d0120 0x18305290 0x02000000 ]",
			expected: nil,
		},
		{
			tname:    "4-byte register with 16-byte data comparison",
			opStr:    "[ cmp gt reg 16 0x0302010a 0x00000000 0x00000000 0x02000001 ]",
			expected: nil,
		},
		{
			tname:    "16-byte register == 4-byte data",
			opStr:    "[ cmp eq reg 1 0x0302010a ]",
			expected: mustCreateComparison(t, linux.NFT_REG_1, linux.NFT_CMP_EQ, []byte{0x0a, 0x01, 0x02, 0x03}),
		},
		{
			tname:    "16-byte register != 4-byte data",
			opStr:    "[ cmp neq reg 2 0x00000064 ]",
			expected: mustCreateComparison(t, linux.NFT_REG_2, linux.NFT_CMP_NEQ, []byte{0x64, 0x00, 0x00, 0x00}),
		},
		{
			tname:    "16-byte register < 4-byte data",
			opStr:    "[ cmp lt reg 3 0x00000000 ]",
			expected: mustCreateComparison(t, linux.NFT_REG_3, linux.NFT_CMP_LT, []byte{0x00, 0x00, 0x00, 0x00}),
		},
		{
			tname:    "16-byte register <= 4-byte data",
			opStr:    "[ cmp lte reg 4 0x00000164 ]",
			expected: mustCreateComparison(t, linux.NFT_REG_4, linux.NFT_CMP_LTE, []byte{0x64, 0x01, 0x00, 0x00}),
		},
		{
			tname:    "16-byte register > 4-byte data",
			opStr:    "[ cmp gt reg 1 0xe8030000 ]",
			expected: mustCreateComparison(t, linux.NFT_REG_1, linux.NFT_CMP_GT, []byte{0x00, 0x00, 0x03, 0xe8}),
		},
		{
			tname:    "16-byte register >= 4-byte data",
			opStr:    "[ cmp gte reg 2 0xc02b0000 ]",
			expected: mustCreateComparison(t, linux.NFT_REG_2, linux.NFT_CMP_GTE, []byte{0x00, 0x00, 0x2b, 0xc0}),
		},
		{
			tname:    "16-byte register == 8-byte data",
			opStr:    "[ cmp eq reg 1 0x0302010a 0x12345678 ]",
			expected: mustCreateComparison(t, linux.NFT_REG_1, linux.NFT_CMP_EQ, []byte{0x0a, 0x01, 0x02, 0x03, 0x78, 0x56, 0x34, 0x12}),
		},
		{
			tname:    "16-byte register != 8-byte data",
			opStr:    "[ cmp neq reg 2 0x00000064 0x00000020 ]",
			expected: mustCreateComparison(t, linux.NFT_REG_2, linux.NFT_CMP_NEQ, []byte{0x64, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00}),
		},
		{
			tname:    "16-byte register < 8-byte data",
			opStr:    "[ cmp lt reg 3 0x00000000 0x00000000 ]",
			expected: mustCreateComparison(t, linux.NFT_REG_3, linux.NFT_CMP_LT, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}),
		},
		{
			tname:    "16-byte register <= 8-byte data",
			opStr:    "[ cmp lte reg 4 0x00000164 0x00000164 ]",
			expected: mustCreateComparison(t, linux.NFT_REG_4, linux.NFT_CMP_LTE, []byte{0x64, 0x01, 0x00, 0x00, 0x64, 0x01, 0x00, 0x00}),
		},
		{
			tname:    "16-byte register > 8-byte data",
			opStr:    "[ cmp gt reg 2 0xe8030000 0x00000f13 ]",
			expected: mustCreateComparison(t, linux.NFT_REG_2, linux.NFT_CMP_GT, []byte{0x00, 0x00, 0x03, 0xe8, 0x13, 0x0f, 0x00, 0x00}),
		},
		{
			tname:    "16-byte register >= 8-byte data",
			opStr:    "[ cmp gte reg 3 0x0a000120 0xc0090000 ]",
			expected: mustCreateComparison(t, linux.NFT_REG_3, linux.NFT_CMP_GTE, []byte{0x20, 0x01, 0x00, 0x0a, 0x00, 0x00, 0x09, 0xc0}),
		},
		{
			tname:    "16-byte register == 12-byte data",
			opStr:    "[ cmp eq reg 1 0x0302010a 0x00000000 0x12345678 ]",
			expected: mustCreateComparison(t, linux.NFT_REG_1, linux.NFT_CMP_EQ, []byte{0x0a, 0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12}),
		},
		{
			tname:    "16-byte register != 12-byte data",
			opStr:    "[ cmp neq reg 2 0x00000064 0x00000000 0x00000020 ]",
			expected: mustCreateComparison(t, linux.NFT_REG_2, linux.NFT_CMP_NEQ, []byte{0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00}),
		},
		{
			tname:    "16-byte register < 12-byte data",
			opStr:    "[ cmp lt reg 3 0x00000000 0x00000000 0x00000000 ]",
			expected: mustCreateComparison(t, linux.NFT_REG_3, linux.NFT_CMP_LT, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}),
		},
		{
			tname:    "16-byte register <= 12-byte data",
			opStr:    "[ cmp lte reg 4 0x00000164 0x00000164 0x00000164 ]",
			expected: mustCreateComparison(t, linux.NFT_REG_4, linux.NFT_CMP_LTE, []byte{0x64, 0x01, 0x00, 0x00, 0x64, 0x01, 0x00, 0x00, 0x64, 0x01, 0x00, 0x00}),
		},
		{
			tname:    "16-byte register > 12-byte data",
			opStr:    "[ cmp gt reg 2 0xe8030000 0x00000f13 0xc0090000 ]",
			expected: mustCreateComparison(t, linux.NFT_REG_2, linux.NFT_CMP_GT, []byte{0x00, 0x00, 0x03, 0xe8, 0x13, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x09, 0xc0}),
		},
		{
			tname:    "16-byte register >= 12-byte data",
			opStr:    "[ cmp gte reg 3 0x0a000120 0x00000f13 0xc0090000 ]",
			expected: mustCreateComparison(t, linux.NFT_REG_3, linux.NFT_CMP_GTE, []byte{0x20, 0x01, 0x00, 0x0a, 0x13, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x09, 0xc0}),
		},
		{
			tname:    "16-byte register == 16-byte data",
			opStr:    "[ cmp eq reg 1 0x0302010a 0x00000000 0x00000000 0x02000002 ]",
			expected: mustCreateComparison(t, linux.NFT_REG_1, linux.NFT_CMP_EQ, []byte{0x0a, 0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x02}),
		},
		{
			tname:    "16-byte register != 16-byte data",
			opStr:    "[ cmp neq reg 2 0x00000064 0x00000000 0x00000000 0x02000000 ]",
			expected: mustCreateComparison(t, linux.NFT_REG_2, linux.NFT_CMP_NEQ, []byte{0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02}),
		},
		{
			tname:    "16-byte register < 16-byte data",
			opStr:    "[ cmp lt reg 3 0x00000000 0x00000000 0x00000000 0x00000000 ]",
			expected: mustCreateComparison(t, linux.NFT_REG_3, linux.NFT_CMP_LT, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}),
		},
		{
			tname:    "16-byte register <= 16-byte data",
			opStr:    "[ cmp lte reg 4 0x00000164 0x00000164 0x00000164 0x00000164 ]",
			expected: mustCreateComparison(t, linux.NFT_REG_4, linux.NFT_CMP_LTE, []byte{0x64, 0x01, 0x00, 0x00, 0x64, 0x01, 0x00, 0x00, 0x64, 0x01, 0x00, 0x00, 0x64, 0x01, 0x00, 0x00}),
		},
		{
			tname:    "16-byte register > 16-byte data",
			opStr:    "[ cmp gt reg 2 0xe8030000 0x00000f13 0xc0090000 0x0b136a87 ]",
			expected: mustCreateComparison(t, linux.NFT_REG_2, linux.NFT_CMP_GT, []byte{0x00, 0x00, 0x03, 0xe8, 0x13, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x09, 0xc0, 0x87, 0x6a, 0x13, 0x0b}),
		},
		{
			tname:    "16-byte register >= 16-byte data",
			opStr:    "[ cmp gte reg 3 0x0a000120 0x00000f13 0xc0090000 0x0b136a87 ]",
			expected: mustCreateComparison(t, linux.NFT_REG_3, linux.NFT_CMP_GTE, []byte{0x20, 0x01, 0x00, 0x0a, 0x13, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x09, 0xc0, 0x87, 0x6a, 0x13, 0x0b}),
		},
	} {
		t.Run(test.tname, func(t *testing.T) { checkOp(t, test, checkComparisonOp) })
	}
}

// checkComparisonOp checks that the given operation is an comparison operation
// and that it matches the expected comparison operation.
func checkComparisonOp(tname string, expected operation, actual operation) error {
	expectedCmp := expected.(*comparison)
	cmp, ok := actual.(*comparison)
	if !ok {
		return fmt.Errorf("expected operation type to be Comparison for %s, got %T", tname, actual)
	}
	if cmp.sreg != expectedCmp.sreg {
		return fmt.Errorf("expected register to be %d for %s, got %d", expectedCmp.sreg, tname, cmp.sreg)
	}
	if cmp.cop != expectedCmp.cop {
		return fmt.Errorf("expected comparison operator to be %v for %s, got %v", expectedCmp.cop, tname, cmp.cop)
	}
	if !cmp.data.equal(expectedCmp.data) {
		return fmt.Errorf("expected data to be %v for %s, got %v", expectedCmp.data, tname, cmp.data)
	}
	return nil
}

// TestInterpretPayloadLoadOps tests interpretation of payload load operations.
// Most operations are direct output of nft binary commands. All stated commands
// should be preceded by nft --debug=netlink to generate matching operations.
func TestInterpretPayloadLoadOps(t *testing.T) {
	for _, test := range []interpretOperationTestAction{
		{
			tname:    "load bytes into verdict register",
			opStr:    "[ payload load 2b @ transport header + 0 => reg 0 ]",
			expected: nil,
		},
		// cmd: add rule ip tab ch tcp flags syn counter accept
		{
			tname:    "load 1 byte into 4-byte register",
			opStr:    "[ payload load 1b @ transport header + 13 => reg 9 ]",
			expected: mustCreatePayloadLoad(t, linux.NFT_PAYLOAD_TRANSPORT_HEADER, 13, 1, linux.NFT_REG32_01),
		},
		{
			tname:    "load 1 byte into 16-byte register",
			opStr:    "[ payload load 1b @ transport header + 13 => reg 1 ]",
			expected: mustCreatePayloadLoad(t, linux.NFT_PAYLOAD_TRANSPORT_HEADER, 13, 1, linux.NFT_REG_1),
		},
		// cmd: add rule ip tab ch tcp sport 80 counter accept
		{
			tname:    "load 2 bytes into 4-byte register no offset",
			opStr:    "[ payload load 2b @ transport header + 0 => reg 8 ]",
			expected: mustCreatePayloadLoad(t, linux.NFT_PAYLOAD_TRANSPORT_HEADER, 0, 2, linux.NFT_REG32_00),
		},
		{
			tname:    "load 2 bytes into 16-byte register no offset",
			opStr:    "[ payload load 2b @ transport header + 0 => reg 1 ]",
			expected: mustCreatePayloadLoad(t, linux.NFT_PAYLOAD_TRANSPORT_HEADER, 0, 2, linux.NFT_REG_1),
		},
		// cmd: add rule ip tab ch tcp dport 12345 counter accept
		{
			tname:    "load 2 bytes into 4-byte register with offset",
			opStr:    "[ payload load 2b @ transport header + 2 => reg 9 ]",
			expected: mustCreatePayloadLoad(t, linux.NFT_PAYLOAD_TRANSPORT_HEADER, 2, 2, linux.NFT_REG32_01),
		},
		{
			tname:    "load 2 bytes into 16-byte register with offset",
			opStr:    "[ payload load 2b @ transport header + 2 => reg 1 ]",
			expected: mustCreatePayloadLoad(t, linux.NFT_PAYLOAD_TRANSPORT_HEADER, 2, 2, linux.NFT_REG_1),
		},
		// cmd: add rule ip tab ch @th,24,24 0xabcdef counter accept
		{
			tname:    "load 3 bytes into 4-byte register",
			opStr:    "[ payload load 3b @ transport header + 3 => reg 10 ]",
			expected: mustCreatePayloadLoad(t, linux.NFT_PAYLOAD_TRANSPORT_HEADER, 3, 3, linux.NFT_REG32_02),
		},
		{
			tname:    "load 3 bytes into 16-byte register",
			opStr:    "[ payload load 3b @ transport header + 3 => reg 2 ]",
			expected: mustCreatePayloadLoad(t, linux.NFT_PAYLOAD_TRANSPORT_HEADER, 3, 3, linux.NFT_REG_2),
		},
		// cmd: add rule ip tab ch ip daddr 192.168.1.1 counter accept
		{
			tname:    "load 4 bytes into 4-byte register",
			opStr:    "[ payload load 4b @ network header + 16 => reg 12 ]",
			expected: mustCreatePayloadLoad(t, linux.NFT_PAYLOAD_NETWORK_HEADER, 16, 4, linux.NFT_REG32_04),
		},
		{
			tname:    "load 4 bytes into 16-byte register",
			opStr:    "[ payload load 4b @ network header + 16 => reg 1 ]",
			expected: mustCreatePayloadLoad(t, linux.NFT_PAYLOAD_NETWORK_HEADER, 16, 4, linux.NFT_REG_1),
		},
		// cmd: add rule ip tab ch ether saddr 01:23:45:67:89:ab counter drop
		{
			tname:    "load 6 bytes into 4-byte register",
			opStr:    "[ payload load 6b @ link header + 6 => reg 13 ]",
			expected: nil,
		},
		{
			tname:    "load 6 bytes into 16-byte register",
			opStr:    "[ payload load 6b @ link header + 6 => reg 3 ]",
			expected: mustCreatePayloadLoad(t, linux.NFT_PAYLOAD_LL_HEADER, 6, 6, linux.NFT_REG_3),
		},
		// cmd: add rule ip6 tab ch ip6 saddr 2001:db8::2 counter accept
		{
			tname:    "load 16 bytes into 4-byte register",
			opStr:    "[ payload load 16b @ network header + 8 => reg 10 ]",
			expected: nil,
		},
		{
			tname:    "load 16 bytes into 16-byte register",
			opStr:    "[ payload load 16b @ network header + 8 => reg 1 ]",
			expected: mustCreatePayloadLoad(t, linux.NFT_PAYLOAD_NETWORK_HEADER, 8, 16, linux.NFT_REG_1),
		},
		{
			tname:    "load >16 bytes into 16-byte register",
			opStr:    "[ payload load 20b @ network header + 16 => reg 1 ]",
			expected: nil,
		},
	} {
		t.Run(test.tname, func(t *testing.T) { checkOp(t, test, checkPayloadLoadOp) })
	}
}

// checkPayloadLoadOp checks that the given operation is a payload load
// operation and that it matches the expected payload load operation.
func checkPayloadLoadOp(tname string, expected operation, actual operation) error {
	expectedPdLoad := expected.(*payloadLoad)
	pdload, ok := actual.(*payloadLoad)
	if !ok {
		return fmt.Errorf("expected operation type to be PayloadLoad for %s, got %T", tname, actual)
	}
	if pdload.base != expectedPdLoad.base {
		return fmt.Errorf("expected payload base to be %v for %s, got %v", expectedPdLoad.base, tname, pdload.base)
	}
	if pdload.offset != expectedPdLoad.offset {
		return fmt.Errorf("expected offset to be %d for %s, got %d", expectedPdLoad.offset, tname, pdload.offset)
	}
	if pdload.blen != expectedPdLoad.blen {
		return fmt.Errorf("expected length to be %d for %s, got %d", expectedPdLoad.blen, tname, pdload.blen)
	}
	if pdload.dreg != expectedPdLoad.dreg {
		return fmt.Errorf("expected destination register to be %d for %s, got %d", expectedPdLoad.dreg, tname, pdload.dreg)
	}
	return nil
}

// TestInterpretPayloadSetOps tests interpretation of payload set operations.
// Most operations are direct output of nft binary commands. All stated commands
// should be preceded by nft --debug=netlink to generate matching operations.
func TestInterpretPayloadSetOps(t *testing.T) {
	for _, test := range []interpretOperationTestAction{
		// Simple checksum type tests.
		{
			tname:    "set checksum type, none",
			opStr:    "[ payload write reg 1 => 6b @ link header + 0 csum_type 0 csum_off 0 csum_flags 0x0 ]",
			expected: mustCreatePayloadSet(t, linux.NFT_PAYLOAD_LL_HEADER, 0, 6, linux.NFT_REG_1, linux.NFT_PAYLOAD_CSUM_NONE, 0, 0x0),
		},
		{
			tname:    "set checksum type, inet",
			opStr:    "[ payload write reg 1 => 6b @ link header + 0 csum_type 1 csum_off 0 csum_flags 0x0 ]",
			expected: mustCreatePayloadSet(t, linux.NFT_PAYLOAD_LL_HEADER, 0, 6, linux.NFT_REG_1, linux.NFT_PAYLOAD_CSUM_INET, 0, 0x0),
		},
		{
			tname:    "set checksum type, sctp", // not supported
			opStr:    "[ payload write reg 1 => 6b @ link header + 0 csum_type 2 csum_off 0 csum_flags 0x0 ]",
			expected: nil,
		},
		{
			tname:    "set out of range checksum type",
			opStr:    "[ payload write reg 1 => 6b @ link header + 0 csum_type 3 csum_off 0 csum_flags 0x0 ]",
			expected: nil,
		},
		// Simple checksum offset tests.
		{
			tname:    "set valid offset",
			opStr:    "[ payload write reg 1 => 6b @ link header + 0 csum_type 0 csum_off 100 csum_flags 0x0 ]",
			expected: mustCreatePayloadSet(t, linux.NFT_PAYLOAD_LL_HEADER, 0, 6, linux.NFT_REG_1, linux.NFT_PAYLOAD_CSUM_NONE, 100, 0x0),
		},
		{
			tname:    "set negative checksum offset",
			opStr:    "[ payload write reg 1 => 6b @ link header + 100 csum_type 1 csum_off -1 csum_flags 0x0 ]",
			expected: nil,
		},
		// Simple checksum flags tests.
		{
			tname:    "set checksum flags, L4 with psuedoheader flag",
			opStr:    "[ payload write reg 1 => 6b @ link header + 0 csum_type 0 csum_off 0 csum_flags 0x1 ]",
			expected: mustCreatePayloadSet(t, linux.NFT_PAYLOAD_LL_HEADER, 0, 6, linux.NFT_REG_1, linux.NFT_PAYLOAD_CSUM_NONE, 0, linux.NFT_PAYLOAD_L4CSUM_PSEUDOHDR),
		},
		{
			tname:    "set invalid checksum flags",
			opStr:    "[ payload write reg 1 => 6b @ link header + 0 csum_type 0 csum_off 0 csum_flags 0x2 ]",
			expected: nil,
		},
		// Invalid register tests.
		{
			tname:    "set from verdict register",
			opStr:    "[ payload write reg 0 => 4b @ link header + 0 csum_type 0 csum_off 0 csum_flags 0x0 ]",
			expected: nil,
		},
		{
			tname:    "set >4 bytes from 4-byte register",
			opStr:    "[ payload write reg 9 => 6b @ link header + 0 csum_type 0 csum_off 0 csum_flags 0x0 ]",
			expected: nil,
		},
		{
			tname:    "set >16 bytes from 16-byte register",
			opStr:    "[ payload write reg 2 => 20b @ link header + 0 csum_type 0 csum_off 0 csum_flags 0x0 ]",
			expected: nil,
		},

		// Valid tests.
		// Note: It doesn't seem like the nft binary ever outputs payload set ops
		// that have an odd offset or length and checksumming on. This makes sense
		// because the offset and length are specified in bytes, but the checksum is
		// calculated in half-words (2-bytes), which means the checksum calculation
		// is only valid if the offset and length are even. However, the linux
		// kernel does not specifically enforce this, so on linux it's technically
		// possible to declare payload set operations that undoubtedly result in
		// invalid checksums. Since the nft binary is what generates our input, we
		// do not test these edge cases either.

		// cmd: add rule ip tab ch @nh,24,8 set 0xab
		{
			tname:    "set 1 byte from 4-byte register with csum NONE and no flags",
			opStr:    "[ payload write reg 8 => 1b @ network header + 3 csum_type 0 csum_off 0 csum_flags 0x0 ]",
			expected: mustCreatePayloadSet(t, linux.NFT_PAYLOAD_NETWORK_HEADER, 3, 1, linux.NFT_REG32_00, linux.NFT_PAYLOAD_CSUM_NONE, 0, 0x0),
		},
		{
			tname:    "set 1 byte from 16-byte register with csum NONE and no flags",
			opStr:    "[ payload write reg 1 => 1b @ network header + 4 csum_type 0 csum_off 0 csum_flags 0x0 ]",
			expected: mustCreatePayloadSet(t, linux.NFT_PAYLOAD_NETWORK_HEADER, 4, 1, linux.NFT_REG_1, linux.NFT_PAYLOAD_CSUM_NONE, 0, 0x0),
		},
		// cmd: add rule ip tab ch tcp sport set 80
		{
			tname:    "set 2 bytes from 4-byte register with csum INET and no flags",
			opStr:    "[ payload write reg 9 => 2b @ transport header + 0 csum_type 1 csum_off 16 csum_flags 0x0 ]",
			expected: mustCreatePayloadSet(t, linux.NFT_PAYLOAD_TRANSPORT_HEADER, 0, 2, linux.NFT_REG32_01, linux.NFT_PAYLOAD_CSUM_INET, 16, 0x0),
		},
		{
			tname:    "set 2 bytes from 16-byte register with csum INET and no flags",
			opStr:    "[ payload write reg 2 => 2b @ transport header + 0 csum_type 1 csum_off 16 csum_flags 0x0 ]",
			expected: mustCreatePayloadSet(t, linux.NFT_PAYLOAD_TRANSPORT_HEADER, 0, 2, linux.NFT_REG_2, linux.NFT_PAYLOAD_CSUM_INET, 16, 0x0),
		},
		// cmd: add rule ip tab ch @ll,24,24 set 0xabcdef
		{
			tname:    "set 3 bytes from 4-byte register with csum NONE and no flags",
			opStr:    "[ payload write reg 10 => 3b @ link header + 3 csum_type 0 csum_off 0 csum_flags 0x0 ]",
			expected: mustCreatePayloadSet(t, linux.NFT_PAYLOAD_LL_HEADER, 3, 3, linux.NFT_REG32_02, linux.NFT_PAYLOAD_CSUM_NONE, 0, 0x0),
		},
		{
			tname:    "set 3 bytes from 16-byte register with csum NONE and no flags",
			opStr:    "[ payload write reg 2 => 3b @ link header + 3 csum_type 0 csum_off 0 csum_flags 0x0 ]",
			expected: mustCreatePayloadSet(t, linux.NFT_PAYLOAD_LL_HEADER, 3, 3, linux.NFT_REG_2, linux.NFT_PAYLOAD_CSUM_NONE, 0, 0x0),
		},
		// cmd: add rule ip tab ch ip daddr set 192.168.1.1
		{
			tname:    "set 4 bytes from 4-byte register with csum INET and pseudoheader flag",
			opStr:    "[ payload write reg 11 => 4b @ network header + 16 csum_type 1 csum_off 10 csum_flags 0x1 ]",
			expected: mustCreatePayloadSet(t, linux.NFT_PAYLOAD_NETWORK_HEADER, 16, 4, linux.NFT_REG32_03, linux.NFT_PAYLOAD_CSUM_INET, 10, linux.NFT_PAYLOAD_L4CSUM_PSEUDOHDR),
		},
		{
			tname:    "set 4 bytes from 4-byte register with csum INET and pseudoheader flag",
			opStr:    "[ payload write reg 3 => 4b @ network header + 16 csum_type 1 csum_off 10 csum_flags 0x1 ]",
			expected: mustCreatePayloadSet(t, linux.NFT_PAYLOAD_NETWORK_HEADER, 16, 4, linux.NFT_REG_3, linux.NFT_PAYLOAD_CSUM_INET, 10, linux.NFT_PAYLOAD_L4CSUM_PSEUDOHDR),
		},
		// cmd: add rule ip tab ch ether saddr set 01:23:45:67:89:ab
		{
			tname:    "set 6 bytes from 16-byte register with csum NONE and no flags",
			opStr:    "[ payload write reg 4 => 6b @ link header + 6 csum_type 0 csum_off 0 csum_flags 0x0 ]",
			expected: mustCreatePayloadSet(t, linux.NFT_PAYLOAD_LL_HEADER, 6, 6, linux.NFT_REG_4, linux.NFT_PAYLOAD_CSUM_NONE, 0, 0x0),
		},
		// cmd: add rule ip6 tab ch ip6 saddr set 2001:db8::2
		{
			tname:    "set 16 bytes from 16-byte register with csum NONE and psuedoheader flag",
			opStr:    "[ payload write reg 1 => 16b @ network header + 8 csum_type 0 csum_off 0 csum_flags 0x1 ]",
			expected: mustCreatePayloadSet(t, linux.NFT_PAYLOAD_NETWORK_HEADER, 8, 16, linux.NFT_REG_1, linux.NFT_PAYLOAD_CSUM_NONE, 0, linux.NFT_PAYLOAD_L4CSUM_PSEUDOHDR),
		},
	} {
		t.Run(test.tname, func(t *testing.T) { checkOp(t, test, checkPayloadSetOp) })
	}
}

// checkPayloadSetOp checks that the given operation is a payload set
// operation and that it matches the expected payload set operation.
func checkPayloadSetOp(tname string, expected operation, actual operation) error {
	expectedPdSet := expected.(*payloadSet)
	pdset, ok := actual.(*payloadSet)
	if !ok {
		return fmt.Errorf("expected operation type to be PayloadLoad for %s, got %T", tname, actual)
	}
	if pdset.base != expectedPdSet.base {
		return fmt.Errorf("expected payload base to be %v for %s, got %v", expectedPdSet.base, tname, pdset.base)
	}
	if pdset.offset != expectedPdSet.offset {
		return fmt.Errorf("expected offset to be %d for %s, got %d", expectedPdSet.offset, tname, pdset.offset)
	}
	if pdset.blen != expectedPdSet.blen {
		return fmt.Errorf("expected length to be %d for %s, got %d", expectedPdSet.blen, tname, pdset.blen)
	}
	if pdset.sreg != expectedPdSet.sreg {
		return fmt.Errorf("expected destination register to be %d for %s, got %d", expectedPdSet.sreg, tname, pdset.sreg)
	}
	if pdset.csumType != expectedPdSet.csumType {
		return fmt.Errorf("expected checksum type to be %d for %s, got %d", expectedPdSet.csumType, tname, pdset.csumType)
	}
	if pdset.csumOffset != expectedPdSet.csumOffset {
		return fmt.Errorf("expected checksum offset to be %d for %s, got %d", expectedPdSet.csumOffset, tname, pdset.csumOffset)
	}
	if pdset.csumFlags != expectedPdSet.csumFlags {
		return fmt.Errorf("expected checksum flags to be %b for %s, got %b", expectedPdSet.csumFlags, tname, pdset.csumFlags)
	}
	return nil
}

// TestInterpretBitwiseOps tests interpretation of bitwise operations.
// Note: Only tests bitwise bool operations for now because interpretation of
// non-boolean operations is not supported from the nft binary debug output.
func TestInterpretBitwiseOps(t *testing.T) {
	for _, test := range []interpretOperationTestAction{
		// Invalid interpretations.
		{
			tname:    "verdict register with bitwise bool",
			opStr:    "[ bitwise reg 0 = ( reg 1 & 0x000003ff ) ^ 0x0000b000 ]",
			expected: nil,
		},
		{
			tname:    "4-byte register with > 4-byte data for bitwise bool",
			opStr:    "[ bitwise reg 1 = ( reg 9 & 0x000003ff 0x09040302 ) ^ 0x0000b000 0x11ff11ff ]",
			expected: nil,
		},
		{
			tname:    "mismatch mask and xor lengths for bitwise bool",
			opStr:    "[ bitwise reg 1 = ( reg 1 & 0x000003ff ) ^ 0x0000b000 0x11ff11ff ]",
			expected: nil,
		},
		// cmd: add rule ip filter input ip dscp set 0x2c
		{
			tname:    "same 4-byte register with 4-byte data for bitwise bool",
			opStr:    "[ bitwise reg 10 = ( reg 10 & 0x000003ff ) ^ 0x0000b000 ]",
			expected: mustCreateBitwiseBool(t, linux.NFT_REG32_02, linux.NFT_REG32_02, []byte{0xff, 0x03, 0x00, 0x00}, []byte{0x00, 0xb0, 0x00, 0x00}),
		},
		{
			tname:    "dif 4-byte registers with 4-byte data for bitwise bool",
			opStr:    "[ bitwise reg 8 = ( reg 9 & 0x000003ff ) ^ 0x0000b000 ]",
			expected: mustCreateBitwiseBool(t, linux.NFT_REG32_01, linux.NFT_REG32_00, []byte{0xff, 0x03, 0x00, 0x00}, []byte{0x00, 0xb0, 0x00, 0x00}),
		},
		// cmd: add rule ip filter input ip saddr and 55 or 0xffff0000 == 34
		{
			tname:    "same 16-byte register with 4-byte data for bitwise bool",
			opStr:    "[ bitwise reg 1 = ( reg 1 & 0x37000000 ) ^ 0x0000ffff ]",
			expected: mustCreateBitwiseBool(t, linux.NFT_REG_1, linux.NFT_REG_1, []byte{0x00, 0x00, 0x00, 0x37}, []byte{0xff, 0xff, 0x00, 0x00}),
		},
		{
			tname:    "dif 16-byte registers with 4-byte data for bitwise bool",
			opStr:    "[ bitwise reg 4 = ( reg 3 & 0x37000000 ) ^ 0x0000ffff ]",
			expected: mustCreateBitwiseBool(t, linux.NFT_REG_3, linux.NFT_REG_4, []byte{0x00, 0x00, 0x00, 0x37}, []byte{0xff, 0xff, 0x00, 0x00}),
		},
		// cmd: add rule ip filter input ip saddr and 0xff0230ff == 5
		{
			tname:    "4- and 16-byte registers with 4-byte data for bitwise bool",
			opStr:    "[ bitwise reg 4 = ( reg 14 & 0xff3002ff ) ^ 0x00000000 ]",
			expected: mustCreateBitwiseBool(t, linux.NFT_REG32_06, linux.NFT_REG_4, []byte{0xff, 0x02, 0x30, 0xff}, []byte{0x00, 0x00, 0x00, 0x00}),
		},
		{
			tname:    "16- and 4-byte registers with 4-byte data for bitwise bool",
			opStr:    "[ bitwise reg 14 = ( reg 1 & 0xff3002ff ) ^ 0x00000000 ]",
			expected: mustCreateBitwiseBool(t, linux.NFT_REG_1, linux.NFT_REG32_06, []byte{0xff, 0x02, 0x30, 0xff}, []byte{0x00, 0x00, 0x00, 0x00}),
		},
		// More than 4 bytes of data.
		{
			tname:    "8-byte data for bitwise bool",
			opStr:    "[ bitwise reg 1 = ( reg 1 & 0x00000000 0x00000000 ) ^ 0x00000164 0x00000164 ]",
			expected: mustCreateBitwiseBool(t, linux.NFT_REG_1, linux.NFT_REG_1, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, []byte{0x64, 0x01, 0x00, 0x00, 0x64, 0x01, 0x00, 0x00}),
		},
		{
			tname:    "12-byte data for bitwise bool",
			opStr:    "[ bitwise reg 4 = ( reg 2 & 0x0302010a 0x00000000 0x12345678 ) ^ 0x0a000120 0x00000f13 0xc0090000 ]",
			expected: mustCreateBitwiseBool(t, linux.NFT_REG_2, linux.NFT_REG_4, []byte{0x0a, 0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12}, []byte{0x20, 0x01, 0x00, 0x0a, 0x13, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x09, 0xc0}),
		},
		{
			tname:    "16-byte data for bitwise bool",
			opStr:    "[ bitwise reg 1 = ( reg 3 & 0xe8030000 0x00000f13 0xc0090000 0x0b136a87 ) ^ 0x0a000120 0x00000f13 0xc0090000 0x00000000 ]",
			expected: mustCreateBitwiseBool(t, linux.NFT_REG_3, linux.NFT_REG_1, []byte{0x00, 0x00, 0x03, 0xe8, 0x13, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x09, 0xc0, 0x87, 0x6a, 0x13, 0x0b}, []byte{0x20, 0x01, 0x00, 0x0a, 0x13, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x09, 0xc0, 0x00, 0x00, 0x00, 0x00}),
		},
	} {
		t.Run(test.tname, func(t *testing.T) { checkOp(t, test, checkBitwiseOp) })
	}
}

// checkBitwiseOp checks that the given operation is a bitwise operation and
// that it matches the expected bitwise operation.
func checkBitwiseOp(tname string, expected operation, actual operation) error {
	expectedBit := expected.(*bitwise)
	bit, ok := actual.(*bitwise)
	if !ok {
		return fmt.Errorf("expected operation type to be BitwiseBool for %s, got %T", tname, actual)
	}
	if bit.sreg != expectedBit.sreg {
		return fmt.Errorf("expected source register to be %d for %s, got %d", expectedBit.sreg, tname, bit.sreg)
	}
	if bit.dreg != expectedBit.dreg {
		return fmt.Errorf("expected destination register to be %d for %s, got %d", expectedBit.dreg, tname, bit.dreg)
	}
	if bit.bop != expectedBit.bop {
		return fmt.Errorf("expected bitwise operation to be %d for %s, got %d", expectedBit.bop, tname, bit.bop)
	}
	if bit.blen != expectedBit.blen {
		return fmt.Errorf("expected bitwise length to be %d for %s, got %d", expectedBit.blen, tname, bit.blen)
	}
	if !bit.mask.equal(expectedBit.mask) {
		return fmt.Errorf("expected bitwise mask to be %v for %s, got %v", expectedBit.mask, tname, bit.mask)
	}
	if !bit.xor.equal(expectedBit.xor) {
		return fmt.Errorf("expected bitwise xor to be %v for %s, got %v", expectedBit.xor, tname, bit.xor)
	}
	if bit.shift != expectedBit.shift {
		return fmt.Errorf("expected bitwise shift to be %d for %s, got %d", expectedBit.shift, tname, bit.shift)
	}
	return nil
}

// TestInterpretCounterOps tests interpretation of counter operations.
// Note: test cases are pretty simple because the counter operation is
// essentially always called with 0 initial bytes and packets.
func TestInterpretCounterOps(t *testing.T) {
	for _, test := range []interpretOperationTestAction{
		{ // cmd: add rule ip tab ch counter
			tname:    "counter with 0 initial bytes and packets",
			opStr:    "[ counter pkts 0 bytes 0 ]",
			expected: newCounter(0, 0),
		},
		{
			tname:    "counter with non-zero initial bytes and packets",
			opStr:    "[ counter pkts 4561 bytes 39 ]",
			expected: newCounter(4561, 39),
		},
	} {
		t.Run(test.tname, func(t *testing.T) { checkOp(t, test, checkCounterOp) })
	}
}

// checkCounterOp checks that the given operation is a counter operation and
// that it matches the expected counter operation.
func checkCounterOp(tname string, expected operation, actual operation) error {
	expectedCntr := expected.(*counter)
	cntr, ok := actual.(*counter)
	if !ok {
		return fmt.Errorf("expected operation type to be Counter for %s, got %T", tname, actual)
	}
	if bytes, expectedBytes := cntr.bytes.Load(), expectedCntr.bytes.Load(); bytes != expectedBytes {
		return fmt.Errorf("expected bytes counter to be %d for %s, got %d", expectedBytes, tname, bytes)
	}
	if pkts, expectedPkts := cntr.packets.Load(), expectedCntr.packets.Load(); pkts != expectedPkts {
		return fmt.Errorf("expected packets counter to be %d for %s, got %d", expectedPkts, tname, pkts)
	}
	return nil
}

// TestInterpretRouteOps tests interpretation of route operations.
func TestInterpretRouteOps(t *testing.T) {
	for _, test := range []interpretOperationTestAction{
		{ // cmd: add rule ip filter output rt nexthop 192.168.1.1
			tname:    "load nexthop4 key to 4-byte register",
			opStr:    "[ rt load nexthop4 => reg 14 ]",
			expected: mustCreateRoute(t, linux.NFT_RT_NEXTHOP4, linux.NFT_REG32_06),
		},
		{ // cmd: add rule ip filter output rt nexthop 192.168.1.9
			tname:    "load nexthop4 key to 4-byte register",
			opStr:    "[ rt load nexthop4 => reg 3 ]",
			expected: mustCreateRoute(t, linux.NFT_RT_NEXTHOP4, linux.NFT_REG_3),
		},
		{ // cmd: add rule ip6 filter output rt nexthop 2001:db8:85a3::aa
			tname:    "load nexthop6 key to 16-byte register",
			opStr:    "[ rt load nexthop6 => reg 1 ]",
			expected: mustCreateRoute(t, linux.NFT_RT_NEXTHOP6, linux.NFT_REG_1),
		},
		{ // cmd: add rule ip filter output rt mtu 1500
			tname:    "load tcpmss key to 4-byte register",
			opStr:    "[ rt load tcpmss => reg 8 ]",
			expected: mustCreateRoute(t, linux.NFT_RT_TCPMSS, linux.NFT_REG32_00),
		},
		{ // cmd: add rule ip filter output rt mtu 0x0102
			tname:    "load tcpmss key to 16-byte register",
			opStr:    "[ rt load tcpmss => reg 4 ]",
			expected: mustCreateRoute(t, linux.NFT_RT_TCPMSS, linux.NFT_REG_4),
		},
		// Result in errors.
		{ // cmd: add rule ip filter output rt classid 0x05
			tname:    "unsupported route key classid",
			opStr:    "[ rt load classid => reg 10 ]",
			expected: nil,
		},
		{ // cmd: add rule ip filter output rt ipsec exists
			tname:    "unsupported route key ipsec",
			opStr:    "[ rt load ipsec => reg 1 ]",
			expected: nil,
		},
		{
			tname:    "invalid route key keyword",
			opStr:    "[ rt load xrfm => reg 1 ]",
			expected: nil,
		},
		{
			tname:    "too few tokens for route operation",
			opStr:    "[ rt nexthop6 => reg 1 ]",
			expected: nil,
		},
		{
			tname:    "too many tokens for route operation",
			opStr:    "[ rt load tcpmss => reg 4 -> reg 5 ]",
			expected: nil,
		},
	} {
		t.Run(test.tname, func(t *testing.T) { checkOp(t, test, checkRouteOp) })
	}
}

// checkRouteOp checks that the given operation is a route operation and
// that it matches the expected route operation.
func checkRouteOp(tname string, expected operation, actual operation) error {
	expectedRt := expected.(*route)
	rt, ok := actual.(*route)
	if !ok {
		return fmt.Errorf("expected operation type to be Route for %s, got %T", tname, actual)
	}
	if rt.key != expectedRt.key {
		return fmt.Errorf("expected route key to be %v for %s, got %v", expectedRt.key, tname, rt.key)
	}
	if rt.dreg != expectedRt.dreg {
		return fmt.Errorf("expected destination register to be %d for %s, got %d", expectedRt.dreg, tname, rt.dreg)
	}
	return nil
}

// TestInterpretByteorderOps tests interpretation of byteorder operations.
// Note: Most byteorder operations have been revealed in the nft binary
// debug output through bitshifts (which oddly do not use the native bitwise
// operation lshift and rshift operators). Thus, many of following commands are
// simply variations of lshift and rshift commands.
func TestInterpretByteorderOps(t *testing.T) {
	for _, test := range []interpretOperationTestAction{
		{ // cmd: add rule ip tab ch tcp dport rshift 4 == 0x5678
			tname:    "ntoh size 2 len 2",
			opStr:    "[ byteorder reg 1 = ntoh(reg 1, 2, 2) ]",
			expected: mustCreateByteorder(t, linux.NFT_REG_1, linux.NFT_REG_1, linux.NFT_BYTEORDER_NTOH, 2, 2),
		},
		{ // cmd: add rule ip tab ch tcp dport rshift 7 == 0x345
			tname:    "ntoh size 2 len 2 again",
			opStr:    "[ byteorder reg 2 = ntoh(reg 11, 2, 2) ]",
			expected: mustCreateByteorder(t, linux.NFT_REG_2, linux.NFT_REG32_03, linux.NFT_BYTEORDER_NTOH, 2, 2),
		},
		{ // cmd: add rule ip filter input @th,24,24 rshift 1 0xabcdef
			tname:    "ntoh size 2 len 3 again",
			opStr:    "[ byteorder reg 15 = ntoh(reg 15, 2, 3) ]",
			expected: mustCreateByteorder(t, linux.NFT_REG32_07, linux.NFT_REG32_07, linux.NFT_BYTEORDER_NTOH, 3, 2),
		},
		{ // cmd: add rule ip filter input ether saddr lshift 1 == 01223456
			tname:    "ntoh size 2 len 6",
			opStr:    "[ byteorder reg 4 = ntoh(reg 3, 2, 6) ]",
			expected: mustCreateByteorder(t, linux.NFT_REG_4, linux.NFT_REG_3, linux.NFT_BYTEORDER_NTOH, 6, 2),
		},
		{ // cmd: add rule ip tab ch ip daddr rshift 20 99900
			tname:    "ntoh size 4 len 4",
			opStr:    "[ byteorder reg 9 = ntoh(reg 1, 4, 4) ]",
			expected: mustCreateByteorder(t, linux.NFT_REG32_01, linux.NFT_REG_1, linux.NFT_BYTEORDER_NTOH, 4, 4),
		},
		{ // cmd: add rule ip6 tab ch ip6 daddr rshift 90 603
			tname:    "ntoh size 8 len 16",
			opStr:    "[ byteorder reg 1 = ntoh(reg 1, 8, 16) ]",
			expected: mustCreateByteorder(t, linux.NFT_REG_1, linux.NFT_REG_1, linux.NFT_BYTEORDER_NTOH, 16, 8),
		},
		{ // cmd: add rule ip filter input meta length gt 1000 accept
			tname:    "hton size 4 len 4",
			opStr:    "[ byteorder reg 8 = hton(reg 1, 4, 4) ]",
			expected: mustCreateByteorder(t, linux.NFT_REG32_00, linux.NFT_REG_1, linux.NFT_BYTEORDER_HTON, 4, 4),
		},
	} {
		t.Run(test.tname, func(t *testing.T) { checkOp(t, test, checkByteorderOp) })
	}
}

// checkByteorderOp checks that the given operation is a byteorder operation
// and that it matches the expected byteorder operation.
func checkByteorderOp(tname string, expected operation, actual operation) error {
	expectedOrder := expected.(*byteorder)
	order, ok := actual.(*byteorder)
	if !ok {
		return fmt.Errorf("expected operation type to be Byteorder for %s, got %T", tname, actual)
	}
	if order.sreg != expectedOrder.sreg {
		return fmt.Errorf("expected source register to be %d for %s, got %d", expectedOrder.sreg, tname, order.sreg)
	}
	if order.dreg != expectedOrder.dreg {
		return fmt.Errorf("expected destination register to be %d for %s, got %d", expectedOrder.dreg, tname, order.dreg)
	}
	if order.bop != expectedOrder.bop {
		return fmt.Errorf("expected byteorder operator to be %v for %s, got %v", expectedOrder.bop, tname, order.bop)
	}
	if order.blen != expectedOrder.blen {
		return fmt.Errorf("expected byteorder length to be %d for %s, got %d", expectedOrder.blen, tname, order.blen)
	}
	if order.size != expectedOrder.size {
		return fmt.Errorf("expected byteorder size to be %d for %s, got %d", expectedOrder.size, tname, order.size)
	}
	return nil
}

// TestInterpretMetaLoadOps tests interpretation of meta load operations.
func TestInterpretMetaLoadOps(t *testing.T) {
	for _, test := range []interpretOperationTestAction{
		{ // cmd: add rule ip tab ch meta length 0x01020304
			tname:    "meta load len test",
			opStr:    "[ meta load len => reg 2 ]",
			expected: mustCreateMetaLoad(t, linux.NFT_META_LEN, linux.NFT_REG_2),
		},
		{ // cmd: add rule inet tab ch meta protocol 0x0102
			tname:    "meta load protocol test",
			opStr:    "[ meta load protocol => reg 3 ]",
			expected: mustCreateMetaLoad(t, linux.NFT_META_PROTOCOL, linux.NFT_REG_3),
		},
		{ // cmd: add rule inet tab ch meta nfproto 253
			tname:    "meta load nfproto test",
			opStr:    "[ meta load nfproto => reg 4 ]",
			expected: mustCreateMetaLoad(t, linux.NFT_META_NFPROTO, linux.NFT_REG_4),
		},
		{ // cmd: add rule inet tab ch meta l4proto 0x17
			tname:    "meta load l4proto test",
			opStr:    "[ meta load l4proto => reg 8 ]",
			expected: mustCreateMetaLoad(t, linux.NFT_META_L4PROTO, linux.NFT_REG32_00),
		},
		{ // cmd: add rule inet tab ch skuid 0x09080706
			tname:    "meta load skuid test",
			opStr:    "[ meta load skuid => reg 10 ]",
			expected: mustCreateMetaLoad(t, linux.NFT_META_SKUID, linux.NFT_REG32_02),
		},
		{ // cmd: add rule inet tab ch meta skgid 0x09080706
			tname:    "meta load skgid test",
			opStr:    "[ meta load skgid => reg 11 ]",
			expected: mustCreateMetaLoad(t, linux.NFT_META_SKGID, linux.NFT_REG32_03),
		},
		{ // cmd: add rule inet tab ch rtclassid 0x01020304
			tname:    "meta load rtclassid test",
			opStr:    "[ meta load rtclassid => reg 12 ]",
			expected: mustCreateMetaLoad(t, linux.NFT_META_RTCLASSID, linux.NFT_REG32_04),
		},
		{ // cmd: add rule inet tab ch pkttype 0x59
			tname:    "meta load pkttype test",
			opStr:    "[ meta load pkttype => reg 13 ]",
			expected: mustCreateMetaLoad(t, linux.NFT_META_PKTTYPE, linux.NFT_REG32_05),
		},
		{ // cmd: add rule inet tab ch meta random 0x02040608
			tname:    "meta load prandom test",
			opStr:    "[ meta load prandom => reg 9 ]",
			expected: mustCreateMetaLoad(t, linux.NFT_META_PRANDOM, linux.NFT_REG32_01),
		},
		{ // cmd: add rule inet tab ch time "2020-06-06 17:00"
			tname:    "meta load arbitrary time test",
			opStr:    "[ meta load time => reg 4 ]",
			expected: mustCreateMetaLoad(t, linux.NFT_META_TIME_NS, linux.NFT_REG_4),
		},
		{ // cmd: add rule inet tab ch time "1970-01-01 00:00:01"
			tname:    "meta load time 1 sec after unix epoch test",
			opStr:    "[ meta load time => reg 3 ]",
			expected: mustCreateMetaLoad(t, linux.NFT_META_TIME_NS, linux.NFT_REG_3),
		},
		{ // cmd: add rule inet tab ch time "1969-01-01 00:00:00"
			tname:    "meta load time 1 year before unix epoch test",
			opStr:    "[ meta load time => reg 2 ]",
			expected: mustCreateMetaLoad(t, linux.NFT_META_TIME_NS, linux.NFT_REG_2),
		},
		{ // cmd: add rule inet tab ch day Monday
			tname:    "meta load day test",
			opStr:    "[ meta load day => reg 23 ]",
			expected: mustCreateMetaLoad(t, linux.NFT_META_TIME_DAY, linux.NFT_REG32_15),
		},
		{ // cmd: add rule inet tab ch hour 0x01020304
			tname:    "meta load hour test",
			opStr:    "[ meta load hour => reg 22 ]",
			expected: mustCreateMetaLoad(t, linux.NFT_META_TIME_HOUR, linux.NFT_REG32_14),
		},
	} {
		t.Run(test.tname, func(t *testing.T) { checkOp(t, test, checkMetaLoadOp) })
	}
}

// checkMetaLoadOp checks that the given operation is a meta load operation and
// that it matches the expected meta load operation.
func checkMetaLoadOp(tname string, expected operation, actual operation) error {
	expectedMtLoad := expected.(*metaLoad)
	mtLoad, ok := actual.(*metaLoad)
	if !ok {
		return fmt.Errorf("expected operation type to be MetaLoad for %s, got %T", tname, actual)
	}
	if mtLoad.key != expectedMtLoad.key {
		return fmt.Errorf("expected meta key to be %v for %s, got %v", expectedMtLoad.key, tname, mtLoad.key)
	}
	if mtLoad.dreg != expectedMtLoad.dreg {
		return fmt.Errorf("expected destination register to be %d for %s, got %d", expectedMtLoad.dreg, tname, mtLoad.dreg)
	}
	return nil
}

// TestInterpretMetaSetOps tests interpretation of meta set operations.
func TestInterpretMetaSetOps(t *testing.T) {
	for _, test := range []interpretOperationTestAction{
		// cmd: nft --debug=netlink add rule ip tab ch meta pkttype set 34
		{
			tname:    "meta set pkttype 4-byte reg test",
			opStr:    "[ meta set pkttype with reg 14 ]",
			expected: mustCreateMetaSet(t, linux.NFT_META_PKTTYPE, linux.NFT_REG32_06),
		},
		{
			tname:    "meta set pkttype 16-byte reg test",
			opStr:    "[ meta set pkttype with reg 3 ]",
			expected: mustCreateMetaSet(t, linux.NFT_META_PKTTYPE, linux.NFT_REG_3),
		},
	} {
		t.Run(test.tname, func(t *testing.T) { checkOp(t, test, checkMetaSetOp) })
	}
}

// checkMetaSetOp checks that the given operation is a meta set operation and
// that it matches the expected meta set operation.
func checkMetaSetOp(tname string, expected operation, actual operation) error {
	expectedMtSet := expected.(*metaSet)
	mtSet, ok := actual.(*metaSet)
	if !ok {
		return fmt.Errorf("expected operation type to be MetaLoad for %s, got %T", tname, actual)
	}
	if mtSet.key != expectedMtSet.key {
		return fmt.Errorf("expected meta key to be %v for %s, got %v", expectedMtSet.key, tname, mtSet.key)
	}
	if mtSet.sreg != expectedMtSet.sreg {
		return fmt.Errorf("expected destination register to be %d for %s, got %d", expectedMtSet.sreg, tname, mtSet.sreg)
	}
	return nil
}

// TestInterpretRule tests the interpretation of basic and general rules as a
// list of operations.
func TestInterpretRule(t *testing.T) {
	for _, test := range []struct {
		tname    string
		ruleStr  string
		expected *Rule // will be nil if an error is expected
	}{
		{
			tname:    "empty ruleset",
			ruleStr:  ``,
			expected: &Rule{},
		},
		{
			tname: "empty ruleset with excess whitespace",
			ruleStr: `		


			`,
			expected: &Rule{},
		},
	} {
		t.Run(test.tname, func(t *testing.T) {
			rule, err := InterpretRule(test.ruleStr)
			if test.expected == nil {
				if err == nil {
					t.Fatalf("unexpected interpretation success for %s", test.tname)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected interpretation error for %s: %v", test.tname, err)
			}

			if len(rule.ops) != len(test.expected.ops) {
				t.Fatalf("expected %d operations for %s, got %d", len(test.expected.ops), test.tname, len(rule.ops))
			}

			// Checks each operation in the rule with the appropriate check function.
			for i, op := range rule.ops {
				testOp := test.expected.ops[i]
				switch testOp.(type) {
				case *immediate:
					if err := checkImmediateOp(test.tname, testOp, op); err != nil {
						t.Fatalf("%s", err.Error())
					}
				case *comparison:
					if err := checkComparisonOp(test.tname, testOp, op); err != nil {
						t.Fatalf("%s", err.Error())
					}
				// TODO(b/345684870): cases will be added here as more types are supported.
				default:
					t.Fatalf("unexpected operation type for %s: %T", test.tname, testOp)
				}
			}
		})
	}
}
