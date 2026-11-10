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

package nvgpu

import (
	"testing"
	"unsafe"
)

// TestNVOS32AllocTiledPitchHeightLayout checks NVOS32AllocTiledPitchHeight
// against NVOS32_PARAMETERS.data.AllocTiledPitchHeight in
// src/common/sdk/nvidia/inc/nvos.h. Drivers from 550 on append an NvS32
// numaNode field, which nvproxy passes through unchanged.
func TestNVOS32AllocTiledPitchHeightLayout(t *testing.T) {
	var p NVOS32AllocTiledPitchHeight
	for _, f := range []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"owner", unsafe.Offsetof(p.Owner), 0},
		{"hMemory", unsafe.Offsetof(p.HMemory), 4},
		{"type", unsafe.Offsetof(p.Type), 8},
		{"flags", unsafe.Offsetof(p.Flags), 12},
		{"height", unsafe.Offsetof(p.Height), 16},
		{"pitch", unsafe.Offsetof(p.Pitch), 20},
		{"attr", unsafe.Offsetof(p.Attr), 24},
		{"width", unsafe.Offsetof(p.Width), 28},
		{"format", unsafe.Offsetof(p.Format), 32},
		{"comprCovg", unsafe.Offsetof(p.ComprCovg), 36},
		{"zcullCovg", unsafe.Offsetof(p.ZcullCovg), 40},
		{"partitionStride", unsafe.Offsetof(p.PartitionStride), 44},
		{"size", unsafe.Offsetof(p.Size), 48},
		{"alignment", unsafe.Offsetof(p.Alignment), 56},
		{"offset", unsafe.Offsetof(p.Offset), 64},
		{"limit", unsafe.Offsetof(p.Limit), 72},
		{"address", unsafe.Offsetof(p.Address), 80},
		{"rangeBegin", unsafe.Offsetof(p.RangeBegin), 88},
		{"rangeEnd", unsafe.Offsetof(p.RangeEnd), 96},
		{"attr2", unsafe.Offsetof(p.Attr2), 104},
		{"ctagOffset", unsafe.Offsetof(p.CtagOffset), 108},
	} {
		if f.got != f.want {
			t.Errorf("offset of %s = %d, want %d", f.name, f.got, f.want)
		}
	}
	var params NVOS32_PARAMETERS
	if unsafe.Sizeof(p) > unsafe.Sizeof(params.Data) {
		t.Errorf("NVOS32AllocTiledPitchHeight is %d bytes, larger than NVOS32_PARAMETERS.Data (%d bytes)", unsafe.Sizeof(p), unsafe.Sizeof(params.Data))
	}
}
