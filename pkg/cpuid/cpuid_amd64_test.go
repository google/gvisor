// Copyright 2019 The gVisor Authors.
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

//go:build amd64
// +build amd64

package cpuid

import (
	"slices"
	"strings"
	"testing"
)

// makeFatureSet creates a new FeatureSet.
func makeFeatureSet(features ...Feature) FeatureSet {
	s := make(Static)
	for _, f := range features {
		s.Add(f)
	}
	return FeatureSet{
		Function: s,
	}
}

var (
	justFPU       = makeFeatureSet(X86FeatureFPU)
	justFPUandPAE = makeFeatureSet(X86FeatureFPU, X86FeaturePAE)
)

func TestSubtract(t *testing.T) {
	if left := justFPU.Subtract(justFPUandPAE); len(left) > 0 {
		t.Errorf("Got %q is not subset of %q, want left (%v) to be non-empty", justFPU.FlagString(), justFPUandPAE.FlagString(), left)
	}
	if left := justFPUandPAE.Subtract(justFPU); len(left) == 0 {
		t.Errorf("Got %q is a subset of %q, want left (%v) to be empty", justFPU.FlagString(), justFPUandPAE.FlagString(), left)
	}
}

// TODO(b/73346484): Run this test on a very old platform, and make sure more
// bits are enabled than just FPU and PAE. This test currently may not detect
// if HostFeatureSet gives back junk bits.
func TestHostFeatureSet(t *testing.T) {
	hostFeatures := HostFeatureSet()
	if justFPUandPAE.Subtract(hostFeatures) != nil {
		t.Errorf("Got invalid feature set %v from HostFeatureSet()", hostFeatures)
	}
}

func TestFixedExtendedState(t *testing.T) {
	hostFeatures := HostFeatureSet()
	fixedFeatures := hostFeatures.Fixed()
	for i, allowed := range allowedBasicFunctions {
		if !allowed {
			continue
		}
		in := In{Eax: uint32(i) + uint32(extendedStart)}
		h := hostFeatures.Query(in)
		f := fixedFeatures.Query(in)
		if h != f {
			t.Errorf("native: %x fixed: %x", h, f)
		}
	}

}

func TestFixedExtendedFeaturesSubleaf1(t *testing.T) {
	for _, tc := range []struct {
		name       string
		maxSubleaf uint32
		out        Out
		want       uint32
	}{
		{name: "Absent"},
		{name: "Unsupported", out: Out{Eax: 1<<4 | 1<<5}},
		{name: "Empty", maxSubleaf: 1},
		{name: "AVXVNNI", maxSubleaf: 1, out: Out{Eax: 1 << 4}, want: 1 << 4},
		{name: "AVX512BF16", maxSubleaf: 1, out: Out{Eax: 1 << 5}, want: 1 << 5},
		{
			name:       "OnlySupportedBits",
			maxSubleaf: 2,
			out:        Out{Eax: 1<<4 | 1<<5 | 1<<10, Ebx: 0xffffffff, Ecx: 0xffffffff, Edx: 0xffffffff},
			want:       1<<4 | 1<<5,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := FeatureSet{Function: Static{
				In{Eax: 0}:         Out{Eax: 7},
				In{Eax: 7}:         Out{Eax: tc.maxSubleaf},
				In{Eax: 7, Ecx: 1}: tc.out,
			}}
			for _, feature := range []struct {
				feature Feature
				bit     uint32
			}{
				{X86FeatureAVX_VNNI, 1 << 4},
				{X86FeatureAVX512_BF16, 1 << 5},
			} {
				if got, want := fs.HasFeature(feature.feature), tc.want&feature.bit != 0; got != want {
					t.Errorf("HasFeature(%v) = %t, want %t", feature.feature, got, want)
				}
			}
			// Host initialization and feature filtering both make static copies.
			for i := 0; i < 2; i++ {
				fs = fs.Fixed()
				if got, want := fs.Query(In{Eax: 7, Ecx: 1}), (Out{Eax: tc.want}); got != want {
					t.Errorf("Fixed iteration %d: CPUID(7, 1) = %+v, want %+v", i, got, want)
				}
				if got := fs.Query(In{Eax: 7}).Eax; got != tc.maxSubleaf {
					t.Errorf("Fixed iteration %d: maximum subleaf = %d, want %d", i, got, tc.maxSubleaf)
				}
			}
		})
	}
}

func TestExtendedFeaturesSubleaf1(t *testing.T) {
	for _, tc := range []struct {
		feature Feature
		name    string
		bit     uint32
	}{
		{X86FeatureAVX_VNNI, "avx_vnni", 1 << 4},
		{X86FeatureAVX512_BF16, "avx512_bf16", 1 << 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, ok := FeatureFromString(tc.name); !ok || got != tc.feature {
				t.Errorf("FeatureFromString(%q) = (%v, %t), want (%v, true)", tc.name, got, ok, tc.feature)
			}
			if !slices.Contains(AllFeatures(), tc.feature) {
				t.Errorf("AllFeatures() missing %v", tc.feature)
			}
			for _, maxSubleaf := range []uint32{0, 2} {
				s := Static{In{Eax: 7}: Out{Eax: maxSubleaf}}
				s.Remove(tc.feature)
				if got := s.Query(In{Eax: 7}).Eax; got != maxSubleaf {
					t.Errorf("Remove on absent feature: maximum subleaf = %d, want %d", got, maxSubleaf)
				}
				s.Add(tc.feature).Add(tc.feature)
				if got, want := s.Query(In{Eax: 7, Ecx: 1}), (Out{Eax: tc.bit}); got != want {
					t.Errorf("Add: CPUID(7, 1) = %+v, want %+v", got, want)
				}
				wantMax := max(maxSubleaf, 1)
				if got := s.Query(In{Eax: 7}).Eax; got != wantMax {
					t.Errorf("Add: maximum subleaf = %d, want %d", got, wantMax)
				}
				if got := s.ToFeatureSet().FlagString(); got != tc.name {
					t.Errorf("FlagString() = %q, want %q", got, tc.name)
				}
				s.Remove(tc.feature)
				if got := s.Query(In{Eax: 7, Ecx: 1}); got != (Out{}) {
					t.Errorf("Remove: CPUID(7, 1) = %+v, want zero", got)
				}
				if got := s.Query(In{Eax: 7}).Eax; got != wantMax {
					t.Errorf("Remove: maximum subleaf = %d, want %d", got, wantMax)
				}
			}
		})
	}
}

func TestIntersectExtendedFeaturesSubleaf1(t *testing.T) {
	fs := FeatureSet{Function: Static{
		In{Eax: 0}:         Out{Eax: 7},
		In{Eax: 7}:         Out{Eax: 1},
		In{Eax: 7, Ecx: 1}: Out{Eax: 1<<4 | 1<<5},
	}}
	for _, tc := range []struct {
		keep    Feature
		missing Feature
		bit     uint32
	}{
		{X86FeatureAVX_VNNI, X86FeatureAVX512_BF16, 1 << 4},
		{X86FeatureAVX512_BF16, X86FeatureAVX_VNNI, 1 << 5},
	} {
		t.Run(tc.keep.String(), func(t *testing.T) {
			filtered, err := fs.Intersect(map[Feature]struct{}{tc.keep: {}})
			if err != nil {
				t.Fatalf("Intersect: %v", err)
			}
			if got, want := filtered.Query(In{Eax: 7, Ecx: 1}), (Out{Eax: tc.bit}); got != want {
				t.Errorf("Intersect: CPUID(7, 1) = %+v, want %+v", got, want)
			}
			missing := fs.Subtract(filtered)
			if _, ok := missing[tc.missing]; len(missing) != 1 || !ok {
				t.Errorf("Subtract = %v, want only %v", missing, tc.missing)
			}
		})
	}
}

func TestHasFeature(t *testing.T) {
	if !justFPU.HasFeature(X86FeatureFPU) {
		t.Errorf("HasFeature failed, %q should contain %v", justFPU.FlagString(), X86FeatureFPU)
	}
	if justFPU.HasFeature(X86FeatureAVX) {
		t.Errorf("HasFeature failed, %q should not contain %v", justFPU.FlagString(), X86FeatureAVX)
	}
}

func TestFeatureNames(t *testing.T) {
	// SPEC_CTRL does not appear in cpuinfo, so FlagString omits it but
	// FeatureNames must include it. Block 7 comes after block 1 in
	// linuxBlockOrder, so it must also come last regardless of insertion order.
	fs := makeFeatureSet(X86FeatureSPEC_CTRL, X86FeaturePAE, X86FeatureFPU)
	if got, want := fs.FeatureNames(), []string{"fpu", "pae", "spec_ctrl"}; !slices.Equal(got, want) {
		t.Errorf("FeatureNames() = %v, want %v", got, want)
	}
	if got, want := fs.FlagString(), "fpu pae"; got != want {
		t.Errorf("FlagString() = %q, want %q", got, want)
	}
	if got := makeFeatureSet().FeatureNames(); len(got) != 0 {
		t.Errorf("FeatureNames() of empty set = %v, want empty", got)
	}
}

func TestFeatureMask(t *testing.T) {
	// X86FeatureSSE3 is block 0 bit 0; X86FeatureFPU is block 1 bit 0;
	// X86FeaturePAE is block 1 bit 6; X86FeatureSPEC_CTRL is block 7 bit 26;
	// X86FeatureAVX_VNNI is block 8 bit 4.
	fs := makeFeatureSet(X86FeatureSSE3, X86FeatureFPU, X86FeaturePAE, X86FeatureSPEC_CTRL, X86FeatureAVX_VNNI)
	const wantMask = "0x00000001,0x00000041,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x04000000,0x00000010"
	if got := fs.FeatureMaskString(); got != wantMask {
		t.Errorf("FeatureMaskString() = %q, want %q", got, wantMask)
	}
	names := fs.FeatureNames()
	gotFromNames, err := FeatureMaskStringFromNames(names)
	if err != nil {
		t.Fatalf("FeatureMaskStringFromNames(%v) unexpected error: %v", names, err)
	}
	if gotFromNames != wantMask {
		t.Errorf("FeatureMaskStringFromNames(%v) = %q, want %q", names, gotFromNames, wantMask)
	}

	const wantEmptyMask = "0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000,0x00000000"
	if got := makeFeatureSet().FeatureMaskString(); got != wantEmptyMask {
		t.Errorf("FeatureMaskString() of empty set = %q, want %q", got, wantEmptyMask)
	}
	if got, err := FeatureMaskStringFromNames(nil); err != nil || got != wantEmptyMask {
		t.Errorf("FeatureMaskStringFromNames(nil) = (%q, %v), want (%q, nil)", got, err, wantEmptyMask)
	}
	if _, err := FeatureMaskStringFromNames([]string{"fpu", "nonexistent"}); err == nil {
		t.Errorf("FeatureMaskStringFromNames with unknown feature succeeded, want error")
	}
}

func TestAdd(t *testing.T) {
	// Test a basic insertion into the FeatureSet.
	testFeatures := makeFeatureSet(X86FeatureCLFSH)
	if !testFeatures.HasFeature(X86FeatureCLFSH) {
		t.Errorf("Add failed, got %v want set with %v", testFeatures, X86FeatureCLFSH)
	}

	// Test that duplicates are ignored.
	testFeatures.Function.(Static).Add(X86FeatureCLFSH)
	if !testFeatures.HasFeature(X86FeatureCLFSH) {
		t.Errorf("Duplicate add removed entry, got %v want set with %v", testFeatures, X86FeatureCLFSH)
	}
}

func TestX86Family(t *testing.T) {
	tests := []struct {
		name string
		sig  uint32
		want uint32
	}{
		{name: "Family6", sig: 0x6 << 8, want: 6},
		{name: "Family6IgnoresExtendedFamily", sig: 0x0a<<20 | 0x6<<8, want: 6},
		{name: "Family0Fh", sig: 0xf << 8, want: 15},
		{name: "Family19h", sig: 0x0a<<20 | 0xf<<8, want: 25},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := x86Family(tc.sig); got != tc.want {
				t.Errorf("x86Family(%#x) = %d, want %d", tc.sig, got, tc.want)
			}
		})
	}
}

func TestWriteCPUInfoFamilyEPYC(t *testing.T) {
	// Overlay an AMD EPYC 7R13-like signature (family 19h) on the host
	// feature set so WriteCPUInfoTo has the rest of the leaves it needs.
	s := HostFeatureSet().ToStatic()
	in := In{Eax: uint32(featureInfo)}
	out := s.Query(in)
	const familyMask = 0x0ff00f00 // extended family 27:20 and family 11:8
	out.Eax = (out.Eax &^ familyMask) | 0x0a<<20 | 0xf<<8
	s.Set(in, out)

	var buf strings.Builder
	s.ToFeatureSet().WriteCPUInfoTo(0, 1, &buf)
	got := buf.String()
	const want = "cpu family\t: 25\n"
	if !strings.Contains(got, want) {
		t.Errorf("WriteCPUInfoTo() missing %q, got:\n%s", want, got)
	}
}

func TestRemove(t *testing.T) {
	// Try removing the last feature.
	testFeatures := makeFeatureSet(X86FeatureFPU, X86FeaturePAE)
	testFeatures.Function.(Static).Remove(X86FeaturePAE)
	if !testFeatures.HasFeature(X86FeatureFPU) || testFeatures.HasFeature(X86FeaturePAE) {
		t.Errorf("Remove failed, got %q want %q", testFeatures.FlagString(), justFPU.FlagString())
	}

	// Try removing a feature not in the set.
	testFeatures.Function.(Static).Remove(X86FeatureRDRAND)
	if !testFeatures.HasFeature(X86FeatureFPU) {
		t.Errorf("Remove failed, got %q want %q", testFeatures.FlagString(), justFPU.FlagString())
	}
}

func TestNormalizeHidesAMX(t *testing.T) {
	amx := []Feature{X86FeatureAMX_BF16, X86FeatureAMX_TILE, X86FeatureAMX_INT8}
	s := make(Static)
	for _, f := range append([]Feature{X86FeatureXSAVE}, amx...) {
		s.Add(f)
	}
	xsave := In{Eax: uint32(xSaveInfo)}
	s.Set(xsave, Out{Eax: uint32(XSAVEFeatureAVX | XCR0AmxCfgMask | XCR0AmxDataMask)})
	avx := In{Eax: uint32(xSaveInfo), Ecx: 2}
	s.Set(avx, Out{Eax: 256, Ebx: 576})
	s.Set(In{Eax: uint32(xSaveInfo), Ecx: amxTileCfgComponent}, Out{Eax: 64, Ebx: 2752})
	s.Set(In{Eax: uint32(xSaveInfo), Ecx: amxTileDataComponent}, Out{Eax: 8192, Ebx: 2816})

	fs := s.ToFeatureSet()
	for _, f := range amx {
		if fs.HasFeature(f) {
			t.Errorf("%v is advertised", f)
		}
	}
	if got, want := fs.Query(xsave).Eax, uint32(XSAVEFeatureAVX); got != want {
		t.Errorf("XCR0 bits: got %#x, want %#x", got, want)
	}
	if got, want := fs.Query(avx), (Out{Eax: 256, Ebx: 576}); got != want {
		t.Errorf("AVX subleaf: got %+v, want %+v", got, want)
	}
	for _, i := range []uint32{amxTileCfgComponent, amxTileDataComponent} {
		if got := fs.Query(In{Eax: uint32(xSaveInfo), Ecx: i}); got != (Out{}) {
			t.Errorf("AMX subleaf %d: got %+v, want zero", i, got)
		}
	}
}

func TestUnsetFSGSBASE(t *testing.T) {
	hostFeatures := HostFeatureSet()
	guestFeatures := hostFeatures.UnsetFSGSBASE()

	if guestFeatures.HasFeature(X86FeatureFSGSBase) {
		t.Errorf("UnsetFSGSBASE failed: X86FeatureFSGSBase should be disabled")
	}

	out := guestFeatures.Query(In{Eax: 7, Ecx: 0})
	if out.Ebx&1 != 0 {
		t.Errorf("UnsetFSGSBASE failed: CPUID.(EAX=7, ECX=0).EBX bit 0 (FSGSBASE) should be 0, got %x", out.Ebx)
	}
}
