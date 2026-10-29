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
	"cmp"
	"encoding/binary"
	"fmt"
	"slices"
)

// Static is a static CPUID function.
type Static map[In]Out

// Fixed converts the FeatureSet to a fixed set.
func (fs FeatureSet) Fixed() FeatureSet {
	sfs := fs.ToStatic().ToFeatureSet()
	sfs.hwCap = fs.hwCap
	return sfs
}

// ToStatic converts a FeatureSet to a Static function.
//
// You can create a new static feature set as:
//
//	fs := otherFeatureSet.ToStatic().ToFeatureSet()
func (fs FeatureSet) ToStatic() Static {
	s := make(Static)

	// Save all allowed top-level functions.
	for fn, allowed := range allowedBasicFunctions {
		if allowed {
			in := In{Eax: uint32(fn)}
			s[in] = fs.Query(in)
		}
	}

	// Save all allowed extended functions.
	for fn, allowed := range allowedExtendedFunctions {
		if allowed {
			in := In{Eax: uint32(fn) + uint32(extendedStart)}
			s[in] = fs.Query(in)
		}
	}

	// Save all features (may be redundant).
	for feature := range allFeatures {
		feature.set(s, fs.HasFeature(feature))
	}

	// Processor Extended State Enumeration.
	for i := uint32(0); i < xSaveInfoNumLeaves; i++ {
		in := In{Eax: uint32(xSaveInfo), Ecx: i}
		s[in] = fs.Query(in)
	}

	// Save all cache information.
	out := fs.Query(In{Eax: uint32(featureInfo)})
	for i := uint32(0); i < out.Ecx; i++ {
		in := In{Eax: uint32(intelDeterministicCacheParams), Ecx: i}
		out := fs.Query(in)
		s[in] = out
		if CacheType(out.Eax&0xf) == cacheNull {
			break
		}
	}

	return s
}

// ToFeatureSet converts a static specification to a FeatureSet.
//
// This overloads some local values, where required.
func (s Static) ToFeatureSet() FeatureSet {
	// Make a copy.
	ns := make(Static)
	for k, v := range s {
		ns[k] = v
	}
	ns.normalize()
	return FeatureSet{ns, hwCap{}}
}

// normalize normalizes extended state information.
func (s Static) normalize() {
	// AMX is not supported, so hide it from applications.
	// TODO(gvisor.dev/issues/9896): Implement AMX support.
	for _, f := range []Feature{X86FeatureAMX_BF16, X86FeatureAMX_TILE, X86FeatureAMX_INT8} {
		s.Remove(f)
	}
	fs := FeatureSet{s, hwCap{}}
	if fs.HasFeature(X86FeatureXSAVE) {
		in := In{Eax: uint32(xSaveInfo)}
		out := s[in]
		// Override local FPU sizes, which must be fixed.
		out.Ecx = max(out.Ecx, maxXsaveSize)
		out.Ebx = max(out.Ebx, xsaveSize)
		out.Eax &^= uint32(XCR0AmxCfgMask | XCR0AmxDataMask)
		s[in] = out
		delete(s, In{Eax: uint32(xSaveInfo), Ecx: amxTileCfgComponent})
		delete(s, In{Eax: uint32(xSaveInfo), Ecx: amxTileDataComponent})
	}
}

// Add adds a feature.
func (s Static) Add(feature Feature) Static {
	feature.set(s, true)
	return s
}

// Remove removes a feature.
func (s Static) Remove(feature Feature) Static {
	feature.set(s, false)
	return s
}

// Set implements ChangeableSet.Set.
func (s Static) Set(in In, out Out) {
	s[in] = out
}

// Query implements Function.Query.
func (s Static) Query(in In) Out {
	in.normalize()
	return s[in]
}

// staticEntrySize is the size of a Static entry in the form of
// Static.marshal.
const staticEntrySize = 6 * 4

// marshal returns s as In.Eax, In.Ecx, Out.Eax, Out.Ebx, Out.Ecx and Out.Edx
// little-endian uint32s for each entry, sorted by input.
func (s Static) marshal() []byte {
	return s.appendMarshal(make([]byte, 0, len(s)*staticEntrySize))
}

// appendMarshal appends the marshaled entries of s to b.
//
// This is how FeatureSet saves Static functions: encoding and decoding the map
// itself (two structs per entry) is much more expensive.
func (s Static) appendMarshal(b []byte) []byte {
	ins := make([]In, 0, len(s))
	for in := range s {
		ins = append(ins, in)
	}
	slices.SortFunc(ins, func(a, b In) int {
		return cmp.Or(cmp.Compare(a.Eax, b.Eax), cmp.Compare(a.Ecx, b.Ecx))
	})
	for _, in := range ins {
		out := s[in]
		for _, v := range [...]uint32{in.Eax, in.Ecx, out.Eax, out.Ebx, out.Ecx, out.Edx} {
			b = binary.LittleEndian.AppendUint32(b, v)
		}
	}
	return b
}

// unmarshalStatic is the inverse of Static.marshal.
func unmarshalStatic(b []byte) (Static, error) {
	if len(b)%staticEntrySize != 0 {
		return nil, fmt.Errorf("invalid static CPUID function length %d", len(b))
	}
	s := make(Static, len(b)/staticEntrySize)
	var prev In
	for i := 0; len(b) > 0; i, b = i+1, b[staticEntrySize:] {
		var v [6]uint32
		for j := range v {
			v[j] = binary.LittleEndian.Uint32(b[4*j:])
		}
		in := In{Eax: v[0], Ecx: v[1]}
		if i > 0 && cmp.Or(cmp.Compare(prev.Eax, in.Eax), cmp.Compare(prev.Ecx, in.Ecx)) >= 0 {
			return nil, fmt.Errorf("unsorted or duplicate CPUID input %+v after %+v", in, prev)
		}
		prev = in
		s[in] = Out{Eax: v[2], Ebx: v[3], Ecx: v[4], Edx: v[5]}
	}
	return s, nil
}
