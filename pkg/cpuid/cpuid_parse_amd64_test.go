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

import "gvisor.dev/gvisor/pkg/hostos"

func archSkipFeature(feature Feature, version hostos.Version) bool {
	switch {
	// Block 0.
	case feature == X86FeatureSDBG && version.AtLeast(4, 3):
		// SDBG only exposed in
		// b1c599b8ff80ea79b9f8277a3f9f36a7b0cfedce (4.3).
		return true
	// Block 2.
	case feature == X86FeatureRDT && version.AtLeast(4, 10):
		// RDT only exposed in
		// 4ab1586488cb56ed8728e54c4157cc38646874d9 (4.10).
		return true
	// Block 3.
	case feature == X86FeatureAVX512VBMI && version.AtLeast(4, 10):
		// AVX512VBMI only exposed in
		// a8d9df5a509a232a959e4ef2e281f7ecd77810d6 (4.10).
		return true
	case feature == X86FeatureUMIP && version.AtLeast(4, 15):
		// UMIP only exposed in
		// 3522c2a6a4f341058b8291326a945e2a2d2aaf55 (4.15).
		return true
	case feature == X86FeaturePKU && version.AtLeast(4, 9):
		// PKU only exposed in
		// dfb4a70f20c5b3880da56ee4c9484bdb4e8f1e65 (4.9).
		return true
	// Block 4.
	case feature == X86FeatureXSAVES && version.AtLeast(4, 8):
		// XSAVES only exposed in
		// b8be15d588060a03569ac85dc4a0247460988f5b (4.8).
		return true
	// Block 5.
	case feature == X86FeaturePERFCTR_LLC && version.AtLeast(4, 14):
		// PERFCTR_LLC renamed in
		// 910448bbed066ab1082b510eef1ae61bb792d854 (4.14).
		return true
	default:
		return false
	}
}
