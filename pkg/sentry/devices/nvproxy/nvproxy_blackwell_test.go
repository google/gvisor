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

package nvproxy

import (
	"testing"

	"gvisor.dev/gvisor/pkg/abi/nvgpu"
	"gvisor.dev/gvisor/pkg/sentry/devices/nvproxy/nvconf"
)

// blackwellClass describes an allocation class that NVIDIA's kernel driver
// exposes on Blackwell GPUs, and which nvproxy must therefore support in order
// for the corresponding workloads to run on those GPUs.
//
// The contents of this table are derived from the driver's own generated
// sources, which are the authoritative statement of what each chip supports:
//
//   - class is the value in src/nvidia/generated/g_allclasses.h.
//   - chips lists the Blackwell chips whose class list contains the class, per
//     gpuGetEngClassDescriptorList_*() and gpuGetNoEngClassList_*() in
//     src/nvidia/generated/g_gpu_class_list.c.
//   - introducedIn is the earliest driver release in which the class appears in
//     g_allclasses.h and src/nvidia/src/kernel/rmapi/resource_list.h.
type blackwellClass struct {
	name         string
	class        nvgpu.ClassID
	chips        string
	introducedIn nvconf.DriverVersion
	wantCaps     nvconf.DriverCaps
}

// blackwellClasses is the complete set of Blackwell-specific allocation classes
// that nvproxy supports. Chip codenames map to products as follows:
// GB100/GB102/GB110/GB112 are datacenter Blackwell (B100/B200/GB200/GB300),
// GB202-GB207 are consumer and workstation Blackwell (GeForce RTX 50 series,
// RTX PRO Blackwell), GB10B is the GB10 superchip (DGX Spark), and GB20B/GB20C
// are Blackwell SoCs (Jetson Thor).
//
// Classes are keyed by the driver version that introduced them, not by the
// nvproxy version tree node that happens to add them: an ABI change must be
// attached to the exact driver release that made it so that later branches
// inherit it correctly. See the "Handling Intermediate Versions" section of
// README.md.
var blackwellClasses = []blackwellClass{
	// Introduced in 560.28.03, along with the first Blackwell chips.
	{"BLACKWELL_A", nvgpu.BLACKWELL_A, "GB100 GB102 GB110 GB112 GB10B", nvconf.NewDriverVersion(560, 28, 3), nvconf.CapGraphics},
	{"BLACKWELL_COMPUTE_A", nvgpu.BLACKWELL_COMPUTE_A, "GB100 GB102 GB110 GB112 GB10B", nvconf.NewDriverVersion(560, 28, 3), compUtil},
	{"BLACKWELL_CHANNEL_GPFIFO_A", nvgpu.BLACKWELL_CHANNEL_GPFIFO_A, "all Blackwell", nvconf.NewDriverVersion(560, 28, 3), compUtil},
	{"BLACKWELL_DMA_COPY_A", nvgpu.BLACKWELL_DMA_COPY_A, "GB100 GB102 GB110 GB112 GB10B GB20B GB20C", nvconf.NewDriverVersion(560, 28, 3), compUtil},
	{"BLACKWELL_INLINE_TO_MEMORY_A", nvgpu.BLACKWELL_INLINE_TO_MEMORY_A, "all Blackwell", nvconf.NewDriverVersion(560, 28, 3), nvconf.CapGraphics},
	{"NVCDB0_VIDEO_DECODER", nvgpu.NVCDB0_VIDEO_DECODER, "GB100 GB102 GB110 GB112", nvconf.NewDriverVersion(560, 28, 3), nvconf.CapVideo},
	{"NVCDD1_VIDEO_NVJPG", nvgpu.NVCDD1_VIDEO_NVJPG, "GB100 GB102 GB110 GB112", nvconf.NewDriverVersion(560, 28, 3), nvconf.CapVideo},
	{"NVCDFA_VIDEO_OFA", nvgpu.NVCDFA_VIDEO_OFA, "GB100 GB102 GB110 GB112", nvconf.NewDriverVersion(560, 28, 3), nvconf.CapVideo},

	// Introduced in 570.86.15, along with the GB20x chips.
	{"BLACKWELL_B", nvgpu.BLACKWELL_B, "GB202 GB203 GB205 GB206 GB207 GB20B GB20C", nvconf.NewDriverVersion(570, 86, 15), nvconf.CapGraphics},
	{"BLACKWELL_COMPUTE_B", nvgpu.BLACKWELL_COMPUTE_B, "GB202 GB203 GB205 GB206 GB207 GB20B GB20C", nvconf.NewDriverVersion(570, 86, 15), compUtil},
	{"BLACKWELL_CHANNEL_GPFIFO_B", nvgpu.BLACKWELL_CHANNEL_GPFIFO_B, "GB202 GB203 GB205 GB206 GB207 GB20B GB20C", nvconf.NewDriverVersion(570, 86, 15), compUtil},
	{"BLACKWELL_DMA_COPY_B", nvgpu.BLACKWELL_DMA_COPY_B, "GB202 GB203 GB205 GB206 GB207 GB20B GB20C", nvconf.NewDriverVersion(570, 86, 15), compUtil},
	{"BLACKWELL_USERMODE_A", nvgpu.BLACKWELL_USERMODE_A, "GB202 GB203 GB205 GB206 GB207 GB20B GB20C", nvconf.NewDriverVersion(570, 86, 15), compUtil},
	{"NVCFB0_VIDEO_DECODER", nvgpu.NVCFB0_VIDEO_DECODER, "GB202 GB203 GB205 GB206 GB207", nvconf.NewDriverVersion(570, 86, 15), nvconf.CapVideo},
	{"NVCFB7_VIDEO_ENCODER", nvgpu.NVCFB7_VIDEO_ENCODER, "GB202 GB203 GB205 GB206 GB207", nvconf.NewDriverVersion(570, 86, 15), nvconf.CapVideo},
	{"NVCFD1_VIDEO_NVJPG", nvgpu.NVCFD1_VIDEO_NVJPG, "GB202 GB203 GB205 GB206", nvconf.NewDriverVersion(570, 86, 15), nvconf.CapVideo},
	{"NVCFFA_VIDEO_OFA", nvgpu.NVCFFA_VIDEO_OFA, "GB202 GB203 GB205 GB206 GB207", nvconf.NewDriverVersion(570, 86, 15), nvconf.CapVideo},

	// Introduced in 580.65.06, along with the Blackwell SoC video engines.
	// NVCED0_VIDEO_NVJPG is the only NVJPG class that GB10B, GB20B and GB20C
	// support, so JPEG decode on those chips depends on it.
	{"NVCEB0_VIDEO_DECODER", nvgpu.NVCEB0_VIDEO_DECODER, "GB10B", nvconf.NewDriverVersion(580, 65, 6), nvconf.CapVideo},
	{"NVCEB7_VIDEO_ENCODER", nvgpu.NVCEB7_VIDEO_ENCODER, "GB10B", nvconf.NewDriverVersion(580, 65, 6), nvconf.CapVideo},
	{"NVCED0_VIDEO_NVJPG", nvgpu.NVCED0_VIDEO_NVJPG, "GB10B GB20B GB20C", nvconf.NewDriverVersion(580, 65, 6), nvconf.CapVideo},
	{"NVCEFA_VIDEO_OFA", nvgpu.NVCEFA_VIDEO_OFA, "GB10B", nvconf.NewDriverVersion(580, 65, 6), nvconf.CapVideo},
	{"NVD1B0_VIDEO_DECODER", nvgpu.NVD1B0_VIDEO_DECODER, "GB20B GB20C", nvconf.NewDriverVersion(580, 65, 6), nvconf.CapVideo},
	{"NVD1B7_VIDEO_ENCODER", nvgpu.NVD1B7_VIDEO_ENCODER, "GB20B GB20C", nvconf.NewDriverVersion(580, 65, 6), nvconf.CapVideo},
	{"NVD1FA_VIDEO_OFA", nvgpu.NVD1FA_VIDEO_OFA, "GB20B GB20C", nvconf.NewDriverVersion(580, 65, 6), nvconf.CapVideo},

	// Introduced in 610.43.02. TRACE_DEVICE_EVENT is supported by every
	// Blackwell chip and is used for device-level GPU tracing.
	{"TRACE_DEVICE_EVENT", nvgpu.TRACE_DEVICE_EVENT, "all Blackwell", nvconf.NewDriverVersion(610, 43, 2), nvconf.CapProfiling},
}

// TestBlackwellClassIDs verifies that nvproxy's Blackwell class IDs match the
// values in the driver's src/nvidia/generated/g_allclasses.h. These are checked
// against literals rather than against the nvgpu constants they come from, so
// that a typo in classes.go is caught here rather than at runtime on a Blackwell
// GPU.
func TestBlackwellClassIDs(t *testing.T) {
	for _, test := range []struct {
		name string
		got  nvgpu.ClassID
		want nvgpu.ClassID
	}{
		{"BLACKWELL_USERMODE_A", nvgpu.BLACKWELL_USERMODE_A, 0x0000c761},
		{"BLACKWELL_CHANNEL_GPFIFO_A", nvgpu.BLACKWELL_CHANNEL_GPFIFO_A, 0x0000c96f},
		{"BLACKWELL_DMA_COPY_A", nvgpu.BLACKWELL_DMA_COPY_A, 0x0000c9b5},
		{"BLACKWELL_CHANNEL_GPFIFO_B", nvgpu.BLACKWELL_CHANNEL_GPFIFO_B, 0x0000ca6f},
		{"BLACKWELL_DMA_COPY_B", nvgpu.BLACKWELL_DMA_COPY_B, 0x0000cab5},
		{"BLACKWELL_INLINE_TO_MEMORY_A", nvgpu.BLACKWELL_INLINE_TO_MEMORY_A, 0x0000cd40},
		{"BLACKWELL_A", nvgpu.BLACKWELL_A, 0x0000cd97},
		{"BLACKWELL_COMPUTE_A", nvgpu.BLACKWELL_COMPUTE_A, 0x0000cdc0},
		{"TRACE_DEVICE_EVENT", nvgpu.TRACE_DEVICE_EVENT, 0x0000cdcd},
		{"BLACKWELL_B", nvgpu.BLACKWELL_B, 0x0000ce97},
		{"BLACKWELL_COMPUTE_B", nvgpu.BLACKWELL_COMPUTE_B, 0x0000cec0},
		{"NVCDB0_VIDEO_DECODER", nvgpu.NVCDB0_VIDEO_DECODER, 0x0000cdb0},
		{"NVCDD1_VIDEO_NVJPG", nvgpu.NVCDD1_VIDEO_NVJPG, 0x0000cdd1},
		{"NVCDFA_VIDEO_OFA", nvgpu.NVCDFA_VIDEO_OFA, 0x0000cdfa},
		{"NVCEB0_VIDEO_DECODER", nvgpu.NVCEB0_VIDEO_DECODER, 0x0000ceb0},
		{"NVCEB7_VIDEO_ENCODER", nvgpu.NVCEB7_VIDEO_ENCODER, 0x0000ceb7},
		{"NVCED0_VIDEO_NVJPG", nvgpu.NVCED0_VIDEO_NVJPG, 0x0000ced0},
		{"NVCEFA_VIDEO_OFA", nvgpu.NVCEFA_VIDEO_OFA, 0x0000cefa},
		{"NVCFB0_VIDEO_DECODER", nvgpu.NVCFB0_VIDEO_DECODER, 0x0000cfb0},
		{"NVCFB7_VIDEO_ENCODER", nvgpu.NVCFB7_VIDEO_ENCODER, 0x0000cfb7},
		{"NVCFD1_VIDEO_NVJPG", nvgpu.NVCFD1_VIDEO_NVJPG, 0x0000cfd1},
		{"NVCFFA_VIDEO_OFA", nvgpu.NVCFFA_VIDEO_OFA, 0x0000cffa},
		{"NVD1B0_VIDEO_DECODER", nvgpu.NVD1B0_VIDEO_DECODER, 0x0000d1b0},
		{"NVD1B7_VIDEO_ENCODER", nvgpu.NVD1B7_VIDEO_ENCODER, 0x0000d1b7},
		{"NVD1FA_VIDEO_OFA", nvgpu.NVD1FA_VIDEO_OFA, 0x0000d1fa},
	} {
		if test.got != test.want {
			t.Errorf("%s = %v, want %v (see src/nvidia/generated/g_allclasses.h)", test.name, test.got, test.want)
		}
	}
}

// TestBlackwellClassCoverage verifies that every driver ABI at or after the
// driver version that introduced a Blackwell class registers a handler for that
// class, and that ABIs before it do not. This guarantees that a newly added
// driver version cannot silently lose Blackwell support by branching from a
// pre-Blackwell node, and that a Blackwell ABI change is never back-dated to a
// driver release that did not contain it.
//
// The check uses driver version ordering as a proxy for ancestry in nvproxy's
// version tree, which holds for every branch in the tree today. If a future
// driver branch makes the two disagree, this table needs a more precise notion
// of "applies to" rather than a looser assertion.
func TestBlackwellClassCoverage(t *testing.T) {
	Init()
	for version, abiEntry := range abis {
		t.Run(version.String(), func(t *testing.T) {
			abi := abiEntry.cons()
			for _, bc := range blackwellClasses {
				handler, ok := abi.allocationClass[bc.class]
				wantSupported := version.IsGreaterThan(bc.introducedIn)
				switch {
				case wantSupported && !ok:
					t.Errorf("driver %s does not support %s (%v), which the driver exposes on %s since %s", version, bc.name, bc.class, bc.chips, bc.introducedIn)
				case !wantSupported && ok:
					t.Errorf("driver %s supports %s (%v), but the driver only added it in %s", version, bc.name, bc.class, bc.introducedIn)
				case ok && handler.capSet != bc.wantCaps:
					t.Errorf("%s (%v) in driver %s is gated on capabilities %q, want %q", bc.name, bc.class, version, handler.capSet, bc.wantCaps)
				}
			}
		})
	}
}

// TestBlackwellSupportedOnLatestDriver verifies that the newest supported driver
// version supports every Blackwell class, i.e. that Blackwell support is not
// stranded on an older branch of the version tree.
func TestBlackwellSupportedOnLatestDriver(t *testing.T) {
	Init()
	var latest nvconf.DriverVersion
	found := false
	for version, abiEntry := range abis {
		if !abiEntry.supported {
			continue
		}
		if !found || version.IsGreaterThan(latest) {
			latest = version
			found = true
		}
	}
	if !found {
		t.Fatal("no supported driver versions")
	}
	abi := abis[latest].cons()
	for _, bc := range blackwellClasses {
		if _, ok := abi.allocationClass[bc.class]; !ok {
			t.Errorf("latest supported driver %s does not support %s (%v)", latest, bc.name, bc.class)
		}
	}
}
