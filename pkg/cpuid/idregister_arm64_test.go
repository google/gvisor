// Copyright 2026 The gVisor Authors.
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

//go:build arm64
// +build arm64

package cpuid

import "testing"

func TestIDRegister(t *testing.T) {
	// A Neoverse V2-like CPU. SVE, SSBS and CPUID aren't in AllowedHWCap1,
	// so no register shows them.
	fs := FeatureSet{
		hwCap: hwCap{hwCap1: HWCAP_FP | HWCAP_ASIMD | HWCAP_AES | HWCAP_PMULL |
			HWCAP_SHA1 | HWCAP_SHA2 | HWCAP_CRC32 | HWCAP_ATOMICS | HWCAP_FPHP |
			HWCAP_ASIMDHP | HWCAP_CPUID | HWCAP_LRCPC | HWCAP_ILRCPC | HWCAP_USCAT |
			HWCAP_SVE | HWCAP_SSBS},
		cpuImplHex: 0x41,
		cpuArchDec: 8,
		cpuVarHex:  0x0,
		cpuPartHex: 0xd4f,
		cpuRevDec:  1,
	}
	for _, tc := range []struct {
		name     string
		crm, op2 uint8
		want     uint64
		ok       bool
	}{
		{name: "MIDR_EL1", crm: 0, op2: 0, want: 0x410fd4f1, ok: true},
		{name: "MPIDR_EL1", crm: 0, op2: 5, want: 0x80000000, ok: true},
		{name: "REVIDR_EL1", crm: 0, op2: 6, want: 0, ok: true},
		{name: "unallocated, CRm 0", crm: 0, op2: 1, ok: false},
		{name: "ID_PFR0_EL1 (AArch32)", crm: 1, op2: 0, ok: false},
		// EL0 and EL1 AArch64, FP and AdvSIMD with half precision, no SVE.
		{name: "ID_AA64PFR0_EL1", crm: 4, op2: 0, want: 0x110011, ok: true},
		// No SSBS.
		{name: "ID_AA64PFR1_EL1", crm: 4, op2: 1, want: 0, ok: true},
		{name: "ID_AA64ZFR0_EL1", crm: 4, op2: 4, want: 0, ok: true},
		// AES with PMULL 2, SHA1 1, SHA2 1, CRC32 1, ATOMIC 2.
		{name: "ID_AA64ISAR0_EL1", crm: 6, op2: 0, want: 0x211120, ok: true},
		// LRCPC with ILRCPC 2.
		{name: "ID_AA64ISAR1_EL1", crm: 6, op2: 1, want: 0x200000, ok: true},
		{name: "ID_AA64MMFR2_EL1", crm: 7, op2: 2, want: 1 << 32, ok: true},
		{name: "reserved, CRm 3", crm: 3, op2: 7, want: 0, ok: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := fs.IDRegister(tc.crm, tc.op2)
			if ok != tc.ok || got != tc.want {
				t.Errorf("IDRegister(%d, %d) = %#x, %v, want %#x, %v", tc.crm, tc.op2, got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestIDRegisterWithoutFP(t *testing.T) {
	got, _ := FeatureSet{}.IDRegister(4, 0)
	// EL0 and EL1 AArch64, FP and AdvSIMD not implemented.
	if want := uint64(0xff0011); got != want {
		t.Errorf("ID_AA64PFR0_EL1 = %#x, want %#x", got, want)
	}
}

func TestEmulateIDRegisterRead(t *testing.T) {
	fs := FeatureSet{
		hwCap:      hwCap{hwCap1: HWCAP_FP | HWCAP_ASIMD | HWCAP_FPHP | HWCAP_ASIMDHP},
		cpuImplHex: 0x4e,
		cpuPartHex: 0x10,
	}
	for _, tc := range []struct {
		name  string
		inst  uint32
		rt    uint32
		value uint64
		ok    bool
	}{
		{name: "mrs x0, midr_el1", inst: 0xd5380000, rt: 0, value: 0x4e0f0100, ok: true},
		{name: "mrs x3, id_aa64pfr0_el1", inst: 0xd5380403, rt: 3, value: 0x110011, ok: true},
		{name: "mrs x30, id_aa64isar1_el1", inst: 0xd538063e, rt: 30, value: 0, ok: true},
		{name: "mrs xzr, id_aa64zfr0_el1", inst: 0xd538049f, rt: 31, value: 0, ok: true},
		{name: "mrs x0, id_pfr0_el1", inst: 0xd5380100},
		{name: "mrs x0, ctr_el0", inst: 0xd53b0020},
		{name: "mrs x0, cntvct_el0", inst: 0xd53be040},
		{name: "msr midr_el1, x0", inst: 0xd5180000},
		{name: "svc #0", inst: 0xd4000001},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, value, ok := fs.EmulateIDRegisterRead(tc.inst)
			if ok != tc.ok || (ok && (rt != tc.rt || value != tc.value)) {
				t.Errorf("EmulateIDRegisterRead(%#08x) = %d, %#x, %v, want %d, %#x, %v", tc.inst, rt, value, ok, tc.rt, tc.value, tc.ok)
			}
		})
	}
}
