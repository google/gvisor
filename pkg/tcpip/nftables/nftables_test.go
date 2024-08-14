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
	"reflect"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	arbitraryTargetChain string        = "target_chain"
	arbitraryHook        Hook          = Prerouting
	arbitraryFamily      AddressFamily = Inet
)

var (
	arbitraryPriority Priority = func() Priority {
		priority, err := NewStandardPriority("filter", arbitraryFamily, arbitraryHook)
		if err != nil {
			panic(fmt.Sprintf("unexpected error for NewStandardPriority: %v", err))
		}
		return priority
	}()
	arbitraryInfoPolicyAccept *BaseChainInfo = &BaseChainInfo{
		BcType:   BaseChainTypeFilter,
		Hook:     arbitraryHook,
		Priority: arbitraryPriority,
	}
)

// makeTestingPacket creates an arbitrary packet for testing.
func makeTestingPacket() *stack.PacketBuffer {
	return stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: 50,
		Payload:            buffer.MakeWithData([]byte{0, 2, 4, 8, 16, 32, 64, 128}),
	})
}

// TestUnsupportedAddressFamily tests that an empty NFTables object returns an
// error when evaluating a packet for an unsupported address family.
func TestUnsupportedAddressFamily(t *testing.T) {
	nf := NewNFTables()
	for _, unsupportedFamily := range []AddressFamily{AddressFamily(NumAFs), AddressFamily(-1)} {
		// Note: the Prerouting hook is arbitrary (any hook would work).
		pkt := makeTestingPacket()
		v, err := nf.EvaluateHook(unsupportedFamily, arbitraryHook, pkt)
		if err == nil {
			t.Fatalf("expecting error for EvaluateHook with unsupported address family %d; got %v verdict, %s packet, and error %v",
				int(unsupportedFamily),
				v, packetResultString(makeTestingPacket(), pkt), err)
		}
	}
}

// TestAcceptAll tests that an empty NFTables object accepts all packets for
// supported hooks and errors for unsupported hooks for all address families
// when evaluating packets at the hook-level.
func TestAcceptAllForSupportedHooks(t *testing.T) {
	for _, family := range []AddressFamily{IP, IP6, Inet, Arp, Bridge, Netdev} {
		t.Run(family.String()+" address family", func(t *testing.T) {
			nf := NewNFTables()
			for _, hook := range []Hook{Prerouting, Input, Forward, Output, Postrouting, Ingress, Egress} {
				pkt := makeTestingPacket()
				v, err := nf.EvaluateHook(family, hook, pkt)

				supported := false
				for _, h := range supportedHooks[family] {
					if h == hook {
						supported = true
						break
					}
				}

				if supported {
					if err != nil || v.Code != VC(linux.NF_ACCEPT) {
						t.Fatalf("expecting accept verdict for EvaluateHook with supported hook %v for family %v; got %v verdict, %s packet, and error %v",
							hook, family,
							v, packetResultString(makeTestingPacket(), pkt), err)
					}
				} else {
					if err == nil {
						t.Fatalf("expecting error for EvaluateHook with unsupported hook %v for family %v; got %v verdict, %s packet, and error %v",
							hook, family,
							v, packetResultString(makeTestingPacket(), pkt), err)
					}
				}
			}
		})
	}
}

// TestEvaluateImmediate tests that the Immediate operation correctly sets the
// register value and behaves as expected during evaluation.
func TestEvaluateImmediate(t *testing.T) {
	for _, test := range []struct {
		tname    string
		baseOp1  Operation // will be nil if unused
		baseOp2  Operation // will be nil if unused
		targetOp Operation // will be nil if unused
		verdict  Verdict
	}{
		{
			tname:   "no operations",
			verdict: Verdict{Code: VC(linux.NF_ACCEPT)}, // from base chain policy
		},
		{
			tname:   "immediately accept",
			baseOp1: mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NF_ACCEPT)})),
			verdict: Verdict{Code: VC(linux.NF_ACCEPT)},
		},
		{
			tname:   "immediately drop",
			baseOp1: mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NF_DROP)})),
			verdict: Verdict{Code: VC(linux.NF_DROP)},
		},
		{
			tname:   "immediately continue with base chain policy accept",
			baseOp1: mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_CONTINUE)})),
			verdict: Verdict{Code: VC(linux.NF_ACCEPT)}, // from base chain policy
		},
		{
			tname:   "immediately return with base chain policy accept",
			baseOp1: mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_RETURN)})),
			verdict: Verdict{Code: VC(linux.NF_ACCEPT)}, // from base chain policy
		},
		{
			tname:    "immediately jump to target chain that accepts",
			baseOp1:  mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_JUMP), ChainName: arbitraryTargetChain})),
			targetOp: mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NF_ACCEPT)})),
			verdict:  Verdict{Code: VC(linux.NF_ACCEPT)},
		},
		{
			tname:    "immediately jump to target chain that drops",
			baseOp1:  mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_JUMP), ChainName: arbitraryTargetChain})),
			targetOp: mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NF_DROP)})),
			verdict:  Verdict{Code: VC(linux.NF_DROP)},
		},
		{
			tname:    "immediately jump to target chain that continues with second rule that accepts",
			baseOp1:  mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_JUMP), ChainName: arbitraryTargetChain})),
			targetOp: mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_CONTINUE)})),
			baseOp2:  mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NF_ACCEPT)})),
			verdict:  Verdict{Code: VC(linux.NF_ACCEPT)},
		},
		{
			tname:    "immediately jump to target chain that continues with second rule that drops",
			baseOp1:  mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_JUMP), ChainName: arbitraryTargetChain})),
			targetOp: mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_CONTINUE)})),
			baseOp2:  mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NF_DROP)})),
			verdict:  Verdict{Code: VC(linux.NF_DROP)},
		},
		{
			tname:    "immediately goto to target chain that accepts",
			baseOp1:  mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_GOTO), ChainName: arbitraryTargetChain})),
			targetOp: mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NF_ACCEPT)})),
			verdict:  Verdict{Code: VC(linux.NF_ACCEPT)},
		},
		{
			tname:    "immediately goto to target chain that drops",
			baseOp1:  mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_GOTO), ChainName: arbitraryTargetChain})),
			targetOp: mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NF_DROP)})),
			verdict:  Verdict{Code: VC(linux.NF_DROP)},
		},
		{
			tname:    "immediately goto to target chain that continues with second rule that accepts",
			baseOp1:  mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_GOTO), ChainName: arbitraryTargetChain})),
			targetOp: mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_CONTINUE)})),
			baseOp2:  mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NF_ACCEPT)})),
			verdict:  Verdict{Code: VC(linux.NF_ACCEPT)}, // from base chain policy
		},
		{
			tname:    "immediately goto to target chain that continues with second rule that drops",
			baseOp1:  mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_GOTO), ChainName: arbitraryTargetChain})),
			targetOp: mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_CONTINUE)})),
			baseOp2:  mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NF_DROP)})),
			verdict:  Verdict{Code: VC(linux.NF_ACCEPT)}, // from base chain policy
		},
		{
			tname:   "add data to register then accept",
			baseOp1: mustCreateImmediate(t, linux.NFT_REG32_13, NewBytesData([]byte{0, 1, 2, 3})),
			baseOp2: mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NF_ACCEPT)})),
			verdict: Verdict{Code: VC(linux.NF_ACCEPT)},
		},
		{
			tname:   "add data to register then drop",
			baseOp1: mustCreateImmediate(t, linux.NFT_REG32_15, NewBytesData([]byte{0, 1, 2, 3})),
			baseOp2: mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NF_DROP)})),
			verdict: Verdict{Code: VC(linux.NF_DROP)},
		},
		{
			tname:   "add data to register then continue",
			baseOp1: mustCreateImmediate(t, linux.NFT_REG_4, NewBytesData([]byte{0, 1, 2, 3})),
			baseOp2: mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_CONTINUE)})),
			verdict: Verdict{Code: VC(linux.NF_ACCEPT)}, // from base chain policy
		},
		{
			tname:   "multiple accepts",
			baseOp1: mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NF_ACCEPT)})),
			baseOp2: mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NF_ACCEPT)})),
			verdict: Verdict{Code: VC(linux.NF_ACCEPT)},
		},
		{
			tname:   "multiple drops",
			baseOp1: mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NF_DROP)})),
			baseOp2: mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NF_DROP)})),
			verdict: Verdict{Code: VC(linux.NF_DROP)},
		},
		{
			tname:   "immediately accept then drop",
			baseOp1: mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NF_ACCEPT)})),
			baseOp2: mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NF_DROP)})),
			verdict: Verdict{Code: VC(linux.NF_ACCEPT)},
		},
		{
			tname:   "immediately drop then accept",
			baseOp1: mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NF_DROP)})),
			baseOp2: mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NF_ACCEPT)})),
			verdict: Verdict{Code: VC(linux.NF_DROP)},
		},
	} {
		t.Run(test.tname, func(t *testing.T) {
			// Sets up an NFTables object with a base chain (for 2 rules) and another
			// target chain (for 1 rule).
			nf := NewNFTables()
			tab, err := nf.AddTable(arbitraryFamily, "test", "test table", false)
			if err != nil {
				t.Fatalf("unexpected error for AddTable: %v", err)
			}
			bc, err := tab.AddChain("base_chain", nil, "test chain", false)
			if err != nil {
				t.Fatalf("unexpected error for AddChain: %v", err)
			}
			bc.SetBaseChainInfo(arbitraryInfoPolicyAccept)
			tc, err := tab.AddChain(arbitraryTargetChain, nil, "test chain", false)
			if err != nil {
				t.Fatalf("unexpected error for AddChain: %v", err)
			}

			// Adds testing rules and operations.
			if test.baseOp1 != nil {
				rule1 := &Rule{}
				rule1.AddOperation(test.baseOp1)
				if err := bc.RegisterRule(rule1, -1); err != nil {
					t.Fatalf("unexpected error for RegisterRule for the first operation: %v", err)
				}
			}
			if test.baseOp2 != nil {
				rule2 := &Rule{}
				rule2.AddOperation(test.baseOp2)
				if err := bc.RegisterRule(rule2, -1); err != nil {
					t.Fatalf("unexpected error for RegisterRule for the second operation: %v", err)
				}
			}
			if test.targetOp != nil {
				ruleTarget := &Rule{}
				ruleTarget.AddOperation(test.targetOp)
				if err := tc.RegisterRule(ruleTarget, -1); err != nil {
					t.Fatalf("unexpected error for RegisterRule for the target operation: %v", err)
				}
			}

			// Runs evaluation and checks verdict.
			pkt := makeTestingPacket()
			v, err := nf.EvaluateHook(arbitraryFamily, arbitraryHook, pkt)

			if err != nil {
				t.Fatalf("unexpected error for EvaluateHook: %v", err)
			}
			if v.Code != test.verdict.Code {
				t.Fatalf("expected verdict %v, got %v", test.verdict, v)
			}
		})
	}
}

// TestLoopCheckOnRegisterAndUnregister tests the loop checking and accompanying
// logic on registering and unregistering rules.
func TestLoopCheckOnRegisterAndUnregister(t *testing.T) {
	for _, test := range []struct {
		tname     string
		chains    map[string]*Chain
		verdict   Verdict
		shouldErr bool
	}{
		{
			tname: "jump to non-existent chain",
			chains: map[string]*Chain{
				"base_chain": &Chain{
					baseChainInfo: arbitraryInfoPolicyAccept,
					rules: []*Rule{&Rule{
						ops: []Operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_JUMP), ChainName: "non_existent_chain"}))},
					}},
				},
			},
			shouldErr: true,
		},
		{
			tname: "goto to non-existent chain",
			chains: map[string]*Chain{
				"base_chain": &Chain{
					baseChainInfo: arbitraryInfoPolicyAccept,
					rules: []*Rule{&Rule{
						ops: []Operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_GOTO), ChainName: "non_existent_chain"}))},
					}},
				},
			},
			shouldErr: true,
		},
		{
			tname: "jump to itself",
			chains: map[string]*Chain{
				"base_chain": &Chain{
					baseChainInfo: arbitraryInfoPolicyAccept,
					rules: []*Rule{&Rule{
						ops: []Operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_JUMP), ChainName: "base_chain"}))},
					}},
				},
			},
			shouldErr: true,
		},
		{
			tname: "goto to itself",
			chains: map[string]*Chain{
				"base_chain": &Chain{
					baseChainInfo: arbitraryInfoPolicyAccept,
					rules: []*Rule{&Rule{
						ops: []Operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_GOTO), ChainName: "base_chain"}))},
					}},
				},
			},
			shouldErr: true,
		},
		{
			tname: "simple 2-chain loop",
			chains: map[string]*Chain{
				"base_chain": &Chain{
					baseChainInfo: arbitraryInfoPolicyAccept,
					rules: []*Rule{&Rule{
						ops: []Operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_JUMP), ChainName: "aux_chain"}))},
					}},
				},
				"aux_chain": &Chain{
					rules: []*Rule{&Rule{
						ops: []Operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_GOTO), ChainName: "base_chain"}))},
					}},
				},
			},
			shouldErr: true,
		},
		{
			tname: "2-chain loop with entry point outside loop",
			chains: map[string]*Chain{
				"base_chain": &Chain{
					baseChainInfo: arbitraryInfoPolicyAccept,
					rules: []*Rule{&Rule{
						ops: []Operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_JUMP), ChainName: "aux_chain"}))},
					}},
				},
				"aux_chain": &Chain{
					rules: []*Rule{&Rule{
						ops: []Operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_GOTO), ChainName: "aux_chain2"}))},
					}},
				},
				"aux_chain2": &Chain{
					rules: []*Rule{&Rule{
						ops: []Operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_GOTO), ChainName: "aux_chain"}))},
					}},
				},
			},
			shouldErr: true,
		},
		{
			tname: "simple 3-chain loop",
			chains: map[string]*Chain{
				"base_chain": &Chain{
					baseChainInfo: arbitraryInfoPolicyAccept,
					rules: []*Rule{&Rule{
						ops: []Operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_JUMP), ChainName: "aux_chain"}))},
					}},
				},
				"aux_chain": &Chain{
					rules: []*Rule{&Rule{
						ops: []Operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_JUMP), ChainName: "aux_chain2"}))},
					}},
				},
				"aux_chain2": &Chain{
					rules: []*Rule{&Rule{
						ops: []Operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_GOTO), ChainName: "base_chain"}))},
					}},
				},
			},
			shouldErr: true,
		},
		{
			tname: "3-chain loop with entry point 2 points outside loop",
			chains: map[string]*Chain{
				"base_chain": &Chain{
					baseChainInfo: arbitraryInfoPolicyAccept,
					rules: []*Rule{&Rule{
						ops: []Operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_JUMP), ChainName: "aux_chain"}))},
					}},
				},
				"aux_chain": &Chain{
					rules: []*Rule{&Rule{
						ops: []Operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_GOTO), ChainName: "aux_chain2"}))},
					}},
				},
				"aux_chain2": &Chain{
					rules: []*Rule{&Rule{
						ops: []Operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_JUMP), ChainName: "aux_chain3"}))},
					}},
				},
				"aux_chain3": &Chain{
					rules: []*Rule{&Rule{
						ops: []Operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_GOTO), ChainName: "aux_chain4"}))},
					}},
				},
				"aux_chain4": &Chain{
					rules: []*Rule{&Rule{
						ops: []Operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_JUMP), ChainName: "aux_chain2"}))},
					}},
				},
			},
			shouldErr: true,
		},
		{
			tname: "simple 4-chain loop",
			chains: map[string]*Chain{
				"base_chain": &Chain{
					baseChainInfo: arbitraryInfoPolicyAccept,
					rules: []*Rule{&Rule{
						ops: []Operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_JUMP), ChainName: "aux_chain"}))},
					}},
				},
				"aux_chain": &Chain{
					rules: []*Rule{&Rule{
						ops: []Operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_GOTO), ChainName: "aux_chain2"}))},
					}},
				},
				"aux_chain2": &Chain{
					rules: []*Rule{&Rule{
						ops: []Operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_JUMP), ChainName: "aux_chain3"}))},
					}},
				},
				"aux_chain3": &Chain{
					rules: []*Rule{&Rule{
						ops: []Operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_GOTO), ChainName: "base_chain"}))},
					}},
				},
			},
			shouldErr: true,
		},
		{
			tname: "simple 5-chain loop",
			chains: map[string]*Chain{
				"base_chain": &Chain{
					baseChainInfo: arbitraryInfoPolicyAccept,
					rules: []*Rule{&Rule{
						ops: []Operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_JUMP), ChainName: "aux_chain"}))},
					}},
				},
				"aux_chain": &Chain{
					rules: []*Rule{&Rule{
						ops: []Operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_GOTO), ChainName: "aux_chain2"}))},
					}},
				},
				"aux_chain2": &Chain{
					rules: []*Rule{&Rule{
						ops: []Operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_JUMP), ChainName: "aux_chain3"}))},
					}},
				},
				"aux_chain3": &Chain{
					rules: []*Rule{&Rule{
						ops: []Operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_GOTO), ChainName: "base_chain"}))},
					}},
				},
			},
			shouldErr: true,
		},
		{
			//     0
			//  	/ \
			//   v   v
			//   1 <- 2 <-> 3
			tname: "complex 2-3 loop",
			chains: map[string]*Chain{
				"base_chain": &Chain{
					baseChainInfo: arbitraryInfoPolicyAccept,
					rules: []*Rule{&Rule{
						ops: []Operation{
							mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_JUMP), ChainName: "aux_chain"})),
							mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_JUMP), ChainName: "aux_chain2"})),
						},
					}},
				},
				"aux_chain": &Chain{
					comment: "strictly target",
					rules: []*Rule{&Rule{
						ops: []Operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NF_DROP)}))},
					}},
				},
				"aux_chain2": &Chain{
					rules: []*Rule{&Rule{
						ops: []Operation{
							mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_JUMP), ChainName: "aux_chain"})),
							mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_JUMP), ChainName: "aux_chain3"})),
						},
					}},
				},
				"aux_chain3": &Chain{
					rules: []*Rule{&Rule{
						ops: []Operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_GOTO), ChainName: "aux_chain2"}))},
					}},
				},
			},
			shouldErr: true,
		},
		{
			tname: "simple loop amongst other rules and operations",
			chains: map[string]*Chain{
				"base_chain": &Chain{
					baseChainInfo: arbitraryInfoPolicyAccept,
					rules: []*Rule{
						&Rule{ops: []Operation{mustCreateImmediate(t, linux.NFT_REG_1, NewBytesData([]byte{0, 1, 2, 3}))}},
						&Rule{ops: []Operation{mustCreateImmediate(t, linux.NFT_REG32_14, NewBytesData([]byte{0, 1, 2, 3}))}},
						&Rule{ops: []Operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_JUMP), ChainName: "aux_chain"}))}},
					},
				},
				"aux_chain": &Chain{
					rules: []*Rule{&Rule{
						ops: []Operation{
							mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NF_DROP)})),
							mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_GOTO), ChainName: "aux_chain2"})),
						},
					}},
				},
				"aux_chain2": &Chain{
					rules: []*Rule{&Rule{
						ops: []Operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_JUMP), ChainName: "aux_chain3"}))},
					}},
				},
				"aux_chain3": &Chain{
					rules: []*Rule{
						&Rule{ops: []Operation{mustCreateImmediate(t, linux.NFT_REG_1, NewBytesData([]byte{0, 1, 2, 3}))}},
						&Rule{ops: []Operation{mustCreateImmediate(t, linux.NFT_REG32_14, NewBytesData([]byte{0, 1, 2, 3}))}},
						&Rule{ops: []Operation{
							mustCreateImmediate(t, linux.NFT_REG_4, NewBytesData([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})),
							mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_GOTO), ChainName: "aux_chain"})),
							mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NF_DROP)})),
						}},
					},
				},
			},
			shouldErr: true,
		},
		{
			tname: "base chain jump to 3 other chains",
			chains: map[string]*Chain{
				"base_chain": &Chain{
					baseChainInfo: arbitraryInfoPolicyAccept,
					rules: []*Rule{
						&Rule{
							ops: []Operation{
								mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_JUMP), ChainName: "aux_chain"})),
								mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_JUMP), ChainName: "aux_chain2"})),
							},
						},
						&Rule{ops: []Operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_JUMP), ChainName: "aux_chain3"}))}},
					},
				},
				"aux_chain": &Chain{
					comment: "strictly target",
					rules: []*Rule{&Rule{
						ops: []Operation{mustCreateImmediate(t, linux.NFT_REG_2, NewBytesData([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}))},
					}},
				},
				"aux_chain2": &Chain{
					comment: "strictly target",
					rules: []*Rule{&Rule{
						ops: []Operation{mustCreateImmediate(t, linux.NFT_REG_3, NewBytesData([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}))},
					}},
				},
				"aux_chain3": &Chain{
					comment: "strictly target",
					rules: []*Rule{&Rule{
						ops: []Operation{mustCreateImmediate(t, linux.NFT_REG_4, NewBytesData([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}))},
					}},
				},
			},
			verdict: Verdict{Code: VC(linux.NF_ACCEPT)}, // from base chain policy
		},
		{
			tname: "base chain jump to 3 other chains with last chain dropping",
			chains: map[string]*Chain{
				"base_chain": &Chain{
					baseChainInfo: arbitraryInfoPolicyAccept,
					rules: []*Rule{
						&Rule{
							ops: []Operation{
								mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_JUMP), ChainName: "aux_chain"})),
								mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_JUMP), ChainName: "aux_chain2"})),
							},
						},
						&Rule{ops: []Operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_JUMP), ChainName: "aux_chain3"}))}},
					},
				},
				"aux_chain": &Chain{
					comment: "strictly target",
					rules: []*Rule{&Rule{
						ops: []Operation{mustCreateImmediate(t, linux.NFT_REG_2, NewBytesData([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}))},
					}},
				},
				"aux_chain2": &Chain{
					comment: "strictly target",
					rules: []*Rule{&Rule{
						ops: []Operation{mustCreateImmediate(t, linux.NFT_REG_3, NewBytesData([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}))},
					}},
				},
				"aux_chain3": &Chain{
					comment: "strictly target",
					rules: []*Rule{&Rule{
						ops: []Operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NF_DROP)}))},
					}},
				},
			},
			verdict: Verdict{Code: VC(linux.NF_DROP)}, // from last chain
		},
		{
			tname: "base chain jump to 3 other chains with last rule in base chain dropping",
			chains: map[string]*Chain{
				"base_chain": &Chain{
					baseChainInfo: arbitraryInfoPolicyAccept,
					rules: []*Rule{
						&Rule{
							ops: []Operation{
								mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_JUMP), ChainName: "aux_chain"})),
								mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_JUMP), ChainName: "aux_chain2"})),
							},
						},
						&Rule{ops: []Operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_JUMP), ChainName: "aux_chain3"}))}},
						&Rule{ops: []Operation{mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NF_DROP)}))}},
					},
				},
				"aux_chain": &Chain{
					comment: "strictly target",
					rules: []*Rule{&Rule{
						ops: []Operation{mustCreateImmediate(t, linux.NFT_REG_2, NewBytesData([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}))},
					}},
				},
				"aux_chain2": &Chain{
					comment: "strictly target",
					rules: []*Rule{&Rule{
						ops: []Operation{mustCreateImmediate(t, linux.NFT_REG_3, NewBytesData([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}))},
					}},
				},
				"aux_chain3": &Chain{
					comment: "strictly target",
					rules: []*Rule{&Rule{
						ops: []Operation{mustCreateImmediate(t, linux.NFT_REG_4, NewBytesData([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}))},
					}},
				},
			},
			verdict: Verdict{Code: VC(linux.NF_DROP)}, // from last rule in base chain
		},
		{
			tname: "jump to the same chain",
			chains: map[string]*Chain{
				"base_chain": &Chain{
					baseChainInfo: arbitraryInfoPolicyAccept,
					rules: []*Rule{
						&Rule{
							ops: []Operation{
								mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_JUMP), ChainName: "aux_chain"})),
								mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NFT_JUMP), ChainName: "aux_chain"})),
							},
						},
					},
				},
				"aux_chain": &Chain{
					comment: "strictly target",
					rules:   []*Rule{&Rule{}},
				},
			},
			verdict: Verdict{Code: VC(linux.NF_ACCEPT)}, // from base chain policy
		},
	} {
		t.Run(test.tname, func(t *testing.T) {
			// Sets up an NFTables object based on test struct.
			nf := NewNFTables()
			tab, err := nf.AddTable(arbitraryFamily, "test", "test table", false)
			if err != nil {
				t.Fatalf("unexpected error for AddTable: %v", err)
			}
			// Creates all chains in the test struct first. This is necessary so the
			// loop checking sees the target chains exist (otherwise it would error).
			for chainName, chainInit := range test.chains {
				tab.AddChain(chainName, chainInit.GetBaseChainInfo(), chainInit.GetComment(), false)
			}
			if len(test.chains) != tab.ChainCount() {
				t.Fatalf("not all chains added to table")
			}
			// Registers all rules to all chains in the test struct.
			for chainName, chainInit := range test.chains {
				chain, err := nf.GetChain(tab.GetAddressFamily(), tab.GetName(), chainName)
				if err != nil {
					t.Fatalf("unexpected error for GetChain: %v", err)
				}
				for _, rule := range chainInit.rules {
					// Note: this is where the loop checking is triggered.
					if err := chain.RegisterRule(rule, -1); err != nil {
						if !test.shouldErr {
							t.Fatalf("unexpected error for RegisterRule: %v", err)
						}
						return
					}
					// Checks that the chain was assigned to the rule.
					if rule.chain == nil {
						t.Fatalf("chain is not assigned to rule after RegisterRule")
					}
				}
				if chainInit.RuleCount() != chain.RuleCount() {
					t.Fatalf("not all rules added to chain")
				}
			}

			// Runs evaluation and checks verdict.
			pkt := makeTestingPacket()
			v, err := nf.EvaluateHook(arbitraryFamily, arbitraryHook, pkt)
			if err != nil {
				if test.verdict.ChainName != "error" {
					t.Fatalf("unexpected error for EvaluateHook: %v", err)
				}
			}
			if v.Code != test.verdict.Code {
				t.Fatalf("expected verdict %v, got %v", test.verdict, v)
			}

			// Unregisters all rules from all chains and checks that the chain is
			// unassigned from the rule.
			for chainName, chainInit := range test.chains {
				chain, err := nf.GetChain(tab.GetAddressFamily(), tab.GetName(), chainName)
				if err != nil {
					t.Fatalf("unexpected error for GetChain: %v", err)
				}
				for rIdx := chainInit.RuleCount() - 1; rIdx >= 0; rIdx-- {
					rule, err := chain.UnregisterRule(rIdx)
					if err != nil {
						t.Fatalf("unexpected error for UnregisterRule: %v", err)
					}
					if rule != chainInit.rules[rIdx] {
						t.Fatalf("rule returned by UnregisterRule does not match previously registered rule")
					}
					if rule.chain != nil {
						t.Fatalf("chain is not unassigned from rule after UnregisterRule")
					}
				}
				if chain.RuleCount() != 0 {
					t.Fatalf("not all rules removed from chain")
				}
			}
		})
	}
}

// TestMaxNestedJumps tests the limit on nested jumps (no limit for gotos).
func TestMaxNestedJumps(t *testing.T) {
	for _, test := range []struct {
		tname         string
		useJumpOp     bool
		numberOfJumps int
		verdict       Verdict // ChainName is set to "error" if an error is expected
	}{
		{
			tname:         "nested jump limit reached with jumps",
			useJumpOp:     true,
			numberOfJumps: nestedJumpLimit,
			verdict:       Verdict{Code: VC(linux.NF_DROP)},
		},
		{
			tname:         "nested jump limit reached with gotos",
			useJumpOp:     false,
			numberOfJumps: nestedJumpLimit,
			verdict:       Verdict{Code: VC(linux.NF_DROP)},
		},
		{
			tname:         "nested jump limit exceeded with jumps",
			useJumpOp:     true,
			numberOfJumps: nestedJumpLimit + 1,
			verdict:       Verdict{ChainName: "error"},
		},
		{
			tname:         "nested jump limit exceeded with gotos",
			useJumpOp:     false,
			numberOfJumps: nestedJumpLimit + 1,
			verdict:       Verdict{Code: VC(linux.NF_DROP)}, // limit only for jumps
		},
	} {
		t.Run(test.tname, func(t *testing.T) {
			// Sets up chains of nested jumps or gotos.
			nf := NewNFTables()
			tab, err := nf.AddTable(arbitraryFamily, "test", "test table", false)
			if err != nil {
				t.Fatalf("unexpected error for AddTable: %v", err)
			}
			for i := test.numberOfJumps - 1; i >= 0; i-- {
				name := fmt.Sprintf("chain %d", i)
				c, err := tab.AddChain(name, nil, "test chain", false)
				if i == 0 {
					c.SetBaseChainInfo(arbitraryInfoPolicyAccept)
				}
				if err != nil {
					t.Fatalf("unexpected error for AddChain: %v", err)
				}
				r := &Rule{}
				if i == test.numberOfJumps-1 {
					err = r.AddOperation(mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: VC(linux.NF_DROP)})))
				} else {
					targetName := fmt.Sprintf("chain %d", i+1)
					code := VC(linux.NFT_JUMP)
					if !test.useJumpOp {
						code = VC(linux.NFT_GOTO)
					}
					err = r.AddOperation(mustCreateImmediate(t, linux.NFT_REG_VERDICT, NewVerdictData(Verdict{Code: code, ChainName: targetName})))
				}
				if err != nil {
					t.Fatalf("unexpected error for AddOperation: %v", err)
				}
				if err := c.RegisterRule(r, -1); err != nil {
					t.Fatalf("unexpected error for RegisterRule: %v", err)
				}
			}

			// Runs evaluation and checks verdict.
			pkt := makeTestingPacket()
			v, err := nf.EvaluateHook(arbitraryFamily, arbitraryHook, pkt)
			if err != nil {
				if test.verdict.ChainName != "error" {
					t.Fatalf("unexpected error for EvaluateHook: %v", err)
				}
			}
			if v.Code != test.verdict.Code {
				t.Fatalf("expected verdict %v, got %v", test.verdict, v)
			}
		})
	}
}

// packetResultString compares 2 packets by equality and returns a string
// representation.
func packetResultString(initial, final *stack.PacketBuffer) string {
	if final == nil {
		return "nil"
	}
	if reflect.DeepEqual(final, initial) {
		return "unmodified"
	}
	return "modified"
}

// mustCreateImmediate wraps the NewImmediate function for brevity.
func mustCreateImmediate(t *testing.T, dreg uint8, data RegisterData) *Immediate {
	imm, err := NewImmediate(dreg, data)
	if err != nil {
		t.Fatalf("failed to create immediate: %v", err)
	}
	return imm
}
