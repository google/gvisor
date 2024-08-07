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

func TestInterpretImmediateOps(t *testing.T) {
	for _, test := range []struct {
		tname string
		opStr string
		op    *Immediate // will be nil if an error is expected
	}{
		{
			tname: "verdict register with accept verdict",
			opStr: "[ immediate reg 0 accept ]",
			op:    mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NF_ACCEPT)})),
		},
		{
			tname: "verdict register with drop verdict",
			opStr: "[ immediate reg 0 drop ]",
			op:    mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NF_DROP)})),
		},
		{
			tname: "verdict register with continue verdict",
			opStr: "[ immediate reg 0 continue ]",
			op:    mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_CONTINUE)})),
		},
		{
			tname: "verdict register with return verdict",
			opStr: "[ immediate reg 0 return ]",
			op:    mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_RETURN)})),
		},
		{
			tname: "verdict register with jump verdict",
			opStr: "[ immediate reg 0 jump -> next_chain ]",
			op:    mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_JUMP), ChainName: "next_chain"})),
		},
		{
			tname: "verdict register with goto verdict",
			opStr: "[ immediate reg 0 goto -> next_chain ]",
			op:    mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_GOTO), ChainName: "next_chain"})),
		},
		{
			tname: "verdict register with 4-byte data",
			opStr: "[ immediate reg 0 0x0201a8c0 ]",
			op:    nil,
		},
		{
			tname: "verdict register with 16-byte data",
			opStr: "[ immediate reg 0 0xb80d0120 0x00000000 0x00000000 0x02000000 ]",
			op:    nil,
		},
		{
			tname: "16-byte register with verdict data",
			opStr: "[ immediate reg 1 accept ]",
			op:    nil,
		},
		{
			tname: "16-byte register with verdict data with target",
			opStr: "[ immediate reg 2 jump -> next_chain ]",
			op:    nil,
		},
		{
			tname: "16-byte register with 4-byte data",
			opStr: "[ immediate reg 3 0x0201a8c0 ]",
			op:    mustCreateImmediate(t, linux.NFT_REG_3, NewBytesData([]byte{0x02, 0x01, 0xa8, 0xc0})),
		},
		{
			tname: "16-byte register with 16-byte data",
			opStr: "[ immediate reg 4 0xb80d0120 0x00000000 0x00000000 0x02000000 ]",
			op:    mustCreateImmediate(t, linux.NFT_REG_4, NewBytesData([]byte{0xb8, 0x0d, 0x01, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00})),
		},
		{
			tname: "16-byte register with 8-byte data",
			opStr: "[ immediate reg 4 0xb80d0120 0x00000050 ]",
			op:    nil,
		},
		{
			tname: "4-byte register with verdict data",
			opStr: "[ immediate reg 8 return ]",
			op:    nil,
		},
		{
			tname: "4-byte register with verdict data with target",
			opStr: "[ immediate reg 9 goto -> next_chain ]",
			op:    nil,
		},
		{
			tname: "4-byte register with 4-byte data",
			opStr: "[ immediate reg 10 0x0201a8c0 ]",
			op:    mustCreateImmediate(t, linux.NFT_REG32_02, NewBytesData([]byte{0x02, 0x01, 0xa8, 0xc0})),
		},
		{
			tname: "4-byte register with 16-byte data",
			opStr: "[ immediate reg 9 0xb80d0120 0x00000000 0x00000000 0x02000000 ]",
			op:    nil,
		},
	} {
		t.Run(test.tname, func(t *testing.T) {
			rule, err := InterpretRule(test.opStr)
			if err != nil {
				if test.op == nil {
					return
				}
				t.Fatalf("unexpected interpretation error for %s: %v", test.tname, err)
			}

			if len(rule.ops) != 1 {
				t.Fatalf("expected single operation for %s, got %d", test.tname, len(rule.ops))
			}
			op := rule.ops[0]
			if err := checkImmediateOp(test.tname, test.op, op); err != nil {
				t.Fatalf(err.Error())
			}
		})
	}
}

func checkImmediateOp(tname string, expected *Immediate, actual Operation) error {
	if actual == nil {
		return fmt.Errorf("expected non-nil operation for %s, got nil", tname)
	}
	imm, ok := actual.(*Immediate)
	if !ok {
		return fmt.Errorf("expected operation type to be Immediate for %s, got %s", tname, actual.TypeString())
	}
	if imm.dreg != expected.dreg {
		return fmt.Errorf("expected register to be %d for %s, got %d", expected.dreg, tname, imm.dreg)
	}
	if !imm.data.Equal(expected.data) {
		return fmt.Errorf("expected data to be %s for %s, got %s", expected.data.String(), tname, imm.data.String())
	}
	return nil
}

func TestInterpretRule(t *testing.T) {
	for _, test := range []struct {
		tname   string
		ruleStr string
		rule    *Rule // will be nil if an error is expected
	}{
		{
			tname:   "empty ruleset",
			ruleStr: ``,
			rule:    &Rule{},
		},
		{
			tname: "empty ruleset with excess whitespace",
			ruleStr: `		


			`,
			rule: &Rule{},
		},
	} {
		t.Run(test.tname, func(t *testing.T) {
			rule, err := InterpretRule(test.ruleStr)
			if err != nil {
				if test.rule == nil {
					return
				}
				t.Fatalf("unexpected interpretation error for %s: %v", test.tname, err)
			}

			if len(rule.ops) != len(test.rule.ops) {
				t.Fatalf("expected %d operations for %s, got %d", len(test.rule.ops), test.tname, len(rule.ops))
			}

			// Checks each operation in the rule with the appropriate check function.
			for i, op := range rule.ops {
				testOp := test.rule.ops[i]
				switch testOp.(type) {
				case *Immediate:
					if err := checkImmediateOp(test.tname, testOp.(*Immediate), op); err != nil {
						t.Fatalf(err.Error())
					}
				// TODO(b/345684870): cases will be added here as more types are supported.
				default:
					t.Fatalf("unexpected operation type for %s: %s", test.tname, testOp.TypeString())
				}
			}
		})
	}
}
