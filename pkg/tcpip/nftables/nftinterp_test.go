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
		t.Fatalf(err.Error())
	}
}

// TestInterpretImmediateOps tests the interpretation of immediate operations.
func TestInterpretImmediateOps(t *testing.T) {
	for _, test := range []interpretOperationTestAction{
		{
			tname:    "verdict register with accept verdict",
			opStr:    "[ immediate reg 0 accept ]",
			expected: mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(Verdict{Code: VC(linux.NF_ACCEPT)})),
		},
		{
			tname:    "verdict register with drop verdict",
			opStr:    "[ immediate reg 0 drop ]",
			expected: mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(Verdict{Code: VC(linux.NF_DROP)})),
		},
		{
			tname:    "verdict register with continue verdict",
			opStr:    "[ immediate reg 0 continue ]",
			expected: mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(Verdict{Code: VC(linux.NFT_CONTINUE)})),
		},
		{
			tname:    "verdict register with return verdict",
			opStr:    "[ immediate reg 0 return ]",
			expected: mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(Verdict{Code: VC(linux.NFT_RETURN)})),
		},
		{
			tname:    "verdict register with jump verdict",
			opStr:    "[ immediate reg 0 jump -> next_chain ]",
			expected: mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(Verdict{Code: VC(linux.NFT_JUMP), ChainName: "next_chain"})),
		},
		{
			tname:    "verdict register with goto verdict",
			opStr:    "[ immediate reg 0 goto -> next_chain ]",
			expected: mustCreateImmediate(t, linux.NFT_REG_VERDICT, newVerdictData(Verdict{Code: VC(linux.NFT_GOTO), ChainName: "next_chain"})),
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
			tname:    "16-byte register with 2-byte data",
			opStr:    "[ immediate reg 2 0xb80d ]",
			expected: nil, // can handle 2-byte data but must be padded to 4-bytes
		},
		{
			tname:    "16-byte register with 4-byte data",
			opStr:    "[ immediate reg 1 0x0201a8c0 ]",
			expected: mustCreateImmediate(t, linux.NFT_REG_1, newBytesData([]byte{0x02, 0x01, 0xa8, 0xc0})),
		},
		{
			tname:    "16-byte register with 6-byte data",
			opStr:    "[ immediate reg 2 0xb80d0120 0x0050 ]",
			expected: nil, // can handle 6-byte data but must be padded to 8-bytes
		},
		{
			tname:    "16-byte register with 8-byte data",
			opStr:    "[ immediate reg 2 0xb80d0120 0x00000050 ]",
			expected: mustCreateImmediate(t, linux.NFT_REG_2, newBytesData([]byte{0xb8, 0x0d, 0x01, 0x20, 0x00, 0x00, 0x00, 0x50})),
		},
		{
			tname:    "16-byte register with 12-byte data",
			opStr:    "[ immediate reg 3 0xb80d0120 0x00000050 0xb80d0120 ]",
			expected: mustCreateImmediate(t, linux.NFT_REG_3, newBytesData([]byte{0xb8, 0x0d, 0x01, 0x20, 0x00, 0x00, 0x00, 0x50, 0xb8, 0x0d, 0x01, 0x20})),
		},
		{
			tname:    "16-byte register with 16-byte data",
			opStr:    "[ immediate reg 4 0xb80d0120 0x00000000 0x00000000 0x02000000 ]",
			expected: mustCreateImmediate(t, linux.NFT_REG_4, newBytesData([]byte{0xb8, 0x0d, 0x01, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00})),
		},
		{
			tname:    "16-byte register with uneven bytes data",
			opStr:    "[ immediate reg 2 0xb80d0120 0x0f60a0 ]",
			expected: nil, // can handle uneven but must be padded to 4-byte multiple
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
			tname:    "4-byte register with 2-byte data",
			opStr:    "[ immediate reg 8 0xb80d ]",
			expected: nil, // can handle 2-byte data but must be padded to 4-bytes
		},
		{
			tname:    "4-byte register with 4-byte data",
			opStr:    "[ immediate reg 10 0x0201a8c0 ]",
			expected: mustCreateImmediate(t, linux.NFT_REG32_02, newBytesData([]byte{0x02, 0x01, 0xa8, 0xc0})),
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

// TestInterpretComparisonOps tests the interpretation of comparison operations.
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
			expected: mustCreateComparison(t, linux.NFT_REG32_00, linux.NFT_CMP_EQ, newBytesData([]byte{0x03, 0x02, 0x01, 0x0a})),
		},
		{
			tname:    "4-byte register != 4-byte data",
			opStr:    "[ cmp neq reg 9 0x00000064 ]",
			expected: mustCreateComparison(t, linux.NFT_REG32_01, linux.NFT_CMP_NEQ, newBytesData([]byte{0x00, 0x00, 0x00, 0x64})),
		},
		{
			tname:    "4-byte register < 4-byte data",
			opStr:    "[ cmp lt reg 10 0x00000000 ]",
			expected: mustCreateComparison(t, linux.NFT_REG32_02, linux.NFT_CMP_LT, newBytesData([]byte{0x00, 0x00, 0x00, 0x00})),
		},
		{
			tname:    "4-byte register <= 4-byte data",
			opStr:    "[ cmp lte reg 11 0x00000164 ]",
			expected: mustCreateComparison(t, linux.NFT_REG32_03, linux.NFT_CMP_LTE, newBytesData([]byte{0x00, 0x00, 0x01, 0x64})),
		},
		{
			tname:    "4-byte register > 4-byte data",
			opStr:    "[ cmp gt reg 12 0xe8030000 ]",
			expected: mustCreateComparison(t, linux.NFT_REG32_04, linux.NFT_CMP_GT, newBytesData([]byte{0xe8, 0x03, 0x00, 0x00})),
		},
		{
			tname:    "4-byte register >= 4-byte data",
			opStr:    "[ cmp gte reg 13 0xc02b0000 ]",
			expected: mustCreateComparison(t, linux.NFT_REG32_05, linux.NFT_CMP_GTE, newBytesData([]byte{0xc0, 0x2b, 0x00, 0x00})),
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
			expected: mustCreateComparison(t, linux.NFT_REG_1, linux.NFT_CMP_EQ, newBytesData([]byte{0x03, 0x02, 0x01, 0x0a})),
		},
		{
			tname:    "16-byte register != 4-byte data",
			opStr:    "[ cmp neq reg 2 0x00000064 ]",
			expected: mustCreateComparison(t, linux.NFT_REG_2, linux.NFT_CMP_NEQ, newBytesData([]byte{0x00, 0x00, 0x00, 0x64})),
		},
		{
			tname:    "16-byte register < 4-byte data",
			opStr:    "[ cmp lt reg 3 0x00000000 ]",
			expected: mustCreateComparison(t, linux.NFT_REG_3, linux.NFT_CMP_LT, newBytesData([]byte{0x00, 0x00, 0x00, 0x00})),
		},
		{
			tname:    "16-byte register <= 4-byte data",
			opStr:    "[ cmp lte reg 4 0x00000164 ]",
			expected: mustCreateComparison(t, linux.NFT_REG_4, linux.NFT_CMP_LTE, newBytesData([]byte{0x00, 0x00, 0x01, 0x64})),
		},
		{
			tname:    "16-byte register > 4-byte data",
			opStr:    "[ cmp gt reg 1 0xe8030000 ]",
			expected: mustCreateComparison(t, linux.NFT_REG_1, linux.NFT_CMP_GT, newBytesData([]byte{0xe8, 0x03, 0x00, 0x00})),
		},
		{
			tname:    "16-byte register >= 4-byte data",
			opStr:    "[ cmp gte reg 2 0xc02b0000 ]",
			expected: mustCreateComparison(t, linux.NFT_REG_2, linux.NFT_CMP_GTE, newBytesData([]byte{0xc0, 0x2b, 0x00, 0x00})),
		},
		{
			tname:    "16-byte register == 8-byte data",
			opStr:    "[ cmp eq reg 1 0x0302010a 0x12345678 ]",
			expected: mustCreateComparison(t, linux.NFT_REG_1, linux.NFT_CMP_EQ, newBytesData([]byte{0x03, 0x02, 0x01, 0x0a, 0x12, 0x34, 0x56, 0x78})),
		},
		{
			tname:    "16-byte register != 8-byte data",
			opStr:    "[ cmp neq reg 2 0x00000064 0x00000020 ]",
			expected: mustCreateComparison(t, linux.NFT_REG_2, linux.NFT_CMP_NEQ, newBytesData([]byte{0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x20})),
		},
		{
			tname:    "16-byte register < 8-byte data",
			opStr:    "[ cmp lt reg 3 0x00000000 0x00000000 ]",
			expected: mustCreateComparison(t, linux.NFT_REG_3, linux.NFT_CMP_LT, newBytesData([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})),
		},
		{
			tname:    "16-byte register <= 8-byte data",
			opStr:    "[ cmp lte reg 4 0x00000164 0x00000164 ]",
			expected: mustCreateComparison(t, linux.NFT_REG_4, linux.NFT_CMP_LTE, newBytesData([]byte{0x00, 0x00, 0x01, 0x64, 0x00, 0x00, 0x01, 0x64})),
		},
		{
			tname:    "16-byte register > 8-byte data",
			opStr:    "[ cmp gt reg 2 0xe8030000 0x00000f13 ]",
			expected: mustCreateComparison(t, linux.NFT_REG_2, linux.NFT_CMP_GT, newBytesData([]byte{0xe8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x13})),
		},
		{
			tname:    "16-byte register >= 8-byte data",
			opStr:    "[ cmp gte reg 3 0x0a000120 0xc0090000 ]",
			expected: mustCreateComparison(t, linux.NFT_REG_3, linux.NFT_CMP_GTE, newBytesData([]byte{0x0a, 0x00, 0x01, 0x20, 0xc0, 0x09, 0x00, 0x00})),
		},
		{
			tname:    "16-byte register == 12-byte data",
			opStr:    "[ cmp eq reg 1 0x0302010a 0x00000000 0x12345678 ]",
			expected: mustCreateComparison(t, linux.NFT_REG_1, linux.NFT_CMP_EQ, newBytesData([]byte{0x03, 0x02, 0x01, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78})),
		},
		{
			tname:    "16-byte register != 12-byte data",
			opStr:    "[ cmp neq reg 2 0x00000064 0x00000000 0x00000020 ]",
			expected: mustCreateComparison(t, linux.NFT_REG_2, linux.NFT_CMP_NEQ, newBytesData([]byte{0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20})),
		},
		{
			tname:    "16-byte register < 12-byte data",
			opStr:    "[ cmp lt reg 3 0x00000000 0x00000000 0x00000000 ]",
			expected: mustCreateComparison(t, linux.NFT_REG_3, linux.NFT_CMP_LT, newBytesData([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})),
		},
		{
			tname:    "16-byte register <= 12-byte data",
			opStr:    "[ cmp lte reg 4 0x00000164 0x00000164 0x00000164 ]",
			expected: mustCreateComparison(t, linux.NFT_REG_4, linux.NFT_CMP_LTE, newBytesData([]byte{0x00, 0x00, 0x01, 0x64, 0x00, 0x00, 0x01, 0x64, 0x00, 0x00, 0x01, 0x64})),
		},
		{
			tname:    "16-byte register > 12-byte data",
			opStr:    "[ cmp gt reg 2 0xe8030000 0x00000f13 0xc0090000 ]",
			expected: mustCreateComparison(t, linux.NFT_REG_2, linux.NFT_CMP_GT, newBytesData([]byte{0xe8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x13, 0xc0, 0x09, 0x00, 0x00})),
		},
		{
			tname:    "16-byte register >= 12-byte data",
			opStr:    "[ cmp gte reg 3 0x0a000120 0x00000f13 0xc0090000 ]",
			expected: mustCreateComparison(t, linux.NFT_REG_3, linux.NFT_CMP_GTE, newBytesData([]byte{0x0a, 0x00, 0x01, 0x20, 0x00, 0x00, 0x0f, 0x13, 0xc0, 0x09, 0x00, 0x00})),
		},
		{
			tname:    "16-byte register == 16-byte data",
			opStr:    "[ cmp eq reg 1 0x0302010a 0x00000000 0x00000000 0x02000002 ]",
			expected: mustCreateComparison(t, linux.NFT_REG_1, linux.NFT_CMP_EQ, newBytesData([]byte{0x03, 0x02, 0x01, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x02})),
		},
		{
			tname:    "16-byte register != 16-byte data",
			opStr:    "[ cmp neq reg 2 0x00000064 0x00000000 0x00000000 0x02000000 ]",
			expected: mustCreateComparison(t, linux.NFT_REG_2, linux.NFT_CMP_NEQ, newBytesData([]byte{0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00})),
		},
		{
			tname:    "16-byte register < 16-byte data",
			opStr:    "[ cmp lt reg 3 0x00000000 0x00000000 0x00000000 0x00000000 ]",
			expected: mustCreateComparison(t, linux.NFT_REG_3, linux.NFT_CMP_LT, newBytesData([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})),
		},
		{
			tname:    "16-byte register <= 16-byte data",
			opStr:    "[ cmp lte reg 4 0x00000164 0x00000164 0x00000164 0x00000164 ]",
			expected: mustCreateComparison(t, linux.NFT_REG_4, linux.NFT_CMP_LTE, newBytesData([]byte{0x00, 0x00, 0x01, 0x64, 0x00, 0x00, 0x01, 0x64, 0x00, 0x00, 0x01, 0x64, 0x00, 0x00, 0x01, 0x64})),
		},
		{
			tname:    "16-byte register > 16-byte data",
			opStr:    "[ cmp gt reg 2 0xe8030000 0x00000f13 0xc0090000 0x0b136a87 ]",
			expected: mustCreateComparison(t, linux.NFT_REG_2, linux.NFT_CMP_GT, newBytesData([]byte{0xe8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x13, 0xc0, 0x09, 0x00, 0x00, 0x0b, 0x13, 0x6a, 0x87})),
		},
		{
			tname:    "16-byte register >= 16-byte data",
			opStr:    "[ cmp gte reg 3 0x0a000120 0x00000f13 0xc0090000 0x0b136a87 ]",
			expected: mustCreateComparison(t, linux.NFT_REG_3, linux.NFT_CMP_GTE, newBytesData([]byte{0x0a, 0x00, 0x01, 0x20, 0x00, 0x00, 0x0f, 0x13, 0xc0, 0x09, 0x00, 0x00, 0x0b, 0x13, 0x6a, 0x87})),
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
						t.Fatalf(err.Error())
					}
				case *comparison:
					if err := checkComparisonOp(test.tname, testOp, op); err != nil {
						t.Fatalf(err.Error())
					}
				// TODO(b/345684870): cases will be added here as more types are supported.
				default:
					t.Fatalf("unexpected operation type for %s: %T", test.tname, testOp)
				}
			}
		})
	}
}
