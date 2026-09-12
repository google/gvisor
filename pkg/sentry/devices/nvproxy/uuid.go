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
	"fmt"
	"reflect"
	"strings"
	"sync"

	"gvisor.dev/gvisor/pkg/abi/nvgpu"
)

// UVM identifies GPUs by UUID rather than by device instance or gpuId: every
// UVM ioctl parameter struct that names a GPU carries an NvProcessorUuid,
// modelled here as nvgpu.NvUUID. After a restore that remapped devices, the
// application passes the UUIDs of the GPUs it had before the checkpoint, which
// the host driver does not recognise -- UVM_MAP_EXTERNAL_ALLOCATION then fails
// with NV_ERR_INVALID_DEVICE, which CUDA reports out of cuMemSetAccess() as
// CUDA_ERROR_INVALID_DEVICE.
//
// Rather than enumerate the parameter types that carry one, nvproxy finds
// every NvUUID inside a parameter struct by walking its type once and caching
// the byte offsets. That cannot miss a parameter type, including the array of
// per-GPU attributes in UVM_MAP_EXTERNAL_ALLOCATION_PARAMS, and it needs no
// per-type method.

// uuidSize is the width of an NvProcessorUuid.
const uuidSize = 16

// uuidOffsetCache memoises uuidOffsetsOf by type.
var uuidOffsetCache sync.Map // reflect.Type -> []int

var nvUUIDType = reflect.TypeOf(nvgpu.NvUUID{})

// uuidOffsetsFor returns the byte offset of every NvUUID inside the type of v,
// computing and caching it on first use.
func uuidOffsetsFor(t reflect.Type) []int {
	if cached, ok := uuidOffsetCache.Load(t); ok {
		return cached.([]int)
	}
	offs := uuidOffsetsOf(t, 0, nil)
	uuidOffsetCache.Store(t, offs)
	return offs
}

// uuidOffsetsOf appends the byte offset of every NvUUID inside t, which itself
// begins at base, to offs.
func uuidOffsetsOf(t reflect.Type, base int, offs []int) []int {
	if t == nvUUIDType {
		return append(offs, base)
	}
	switch t.Kind() {
	case reflect.Struct:
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			offs = uuidOffsetsOf(f.Type, base+int(f.Offset), offs)
		}
	case reflect.Array:
		elem := t.Elem()
		// Skip arrays that cannot contain a UUID, which is most of them.
		if !typeMayContainUUID(elem) {
			return offs
		}
		stride := int(elem.Size())
		for i := 0; i < t.Len(); i++ {
			offs = uuidOffsetsOf(elem, base+i*stride, offs)
		}
	}
	return offs
}

// typeMayContainUUID reports whether t is, or transitively contains, an
// NvUUID. It exists so that uuidOffsetsOf does not walk every element of a
// large array of scalars.
func typeMayContainUUID(t reflect.Type) bool {
	if t == nvUUIDType {
		return true
	}
	switch t.Kind() {
	case reflect.Struct:
		for i := 0; i < t.NumField(); i++ {
			if typeMayContainUUID(t.Field(i).Type) {
				return true
			}
		}
	case reflect.Array:
		return typeMayContainUUID(t.Elem())
	}
	return false
}

// formatUUID renders a raw 16-byte processor UUID the way `nvidia-smi -L` and
// nvproxy's DeviceRemapID.UUID do.
func formatUUID(b []byte) string {
	if len(b) < uuidSize {
		return "<short>"
	}
	var zero bool = true
	for _, c := range b[:uuidSize] {
		if c != 0 {
			zero = false
			break
		}
	}
	if zero {
		// The CPU's processor UUID, and the value of an unused slot.
		return "<zero>"
	}
	return fmt.Sprintf("GPU-%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
		b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
}

// translateUUIDsInBuf rewrites every UUID at the given offsets in buf using m,
// which is keyed and valued by the "GPU-..." string form. It returns the
// translations it made, for logging.
func translateUUIDsInBuf(buf []byte, offs []int, m map[string]string) [][2]string {
	if len(m) == 0 || len(offs) == 0 {
		return nil
	}
	var done [][2]string
	for _, off := range offs {
		if off+uuidSize > len(buf) {
			continue
		}
		from := formatUUID(buf[off:])
		to, ok := m[from]
		if !ok {
			continue
		}
		toBin, ok := uuidBinary(to)
		if !ok {
			continue
		}
		copy(buf[off:off+uuidSize], toBin[:])
		done = append(done, [2]string{from, to})
	}
	return done
}

// describeUUIDsInBuf renders every non-zero UUID at the given offsets, for a
// log line.
func describeUUIDsInBuf(buf []byte, offs []int) string {
	var b strings.Builder
	b.WriteByte('[')
	n := 0
	for _, off := range offs {
		if off+uuidSize > len(buf) {
			continue
		}
		s := formatUUID(buf[off:])
		if s == "<zero>" {
			continue
		}
		if n != 0 {
			b.WriteString(", ")
		}
		b.WriteString(s)
		n++
	}
	b.WriteByte(']')
	return b.String()
}

// uvmIoctlLogsUUIDs reports whether a UVM ioctl's UUIDs are worth an Info line.
// These are the ioctls by which the application builds its view of which GPUs
// exist and which may reach which memory -- the ones a wrong UUID breaks.
var uvmIoctlLogsUUIDs = map[uint32]struct{}{
	nvgpu.UVM_REGISTER_GPU:                   {},
	nvgpu.UVM_UNREGISTER_GPU:                 {},
	nvgpu.UVM_REGISTER_GPU_VASPACE:           {},
	nvgpu.UVM_UNREGISTER_GPU_VASPACE:         {},
	nvgpu.UVM_ENABLE_PEER_ACCESS:             {},
	nvgpu.UVM_DISABLE_PEER_ACCESS:            {},
	nvgpu.UVM_MAP_EXTERNAL_ALLOCATION:        {},
	nvgpu.UVM_ALLOC_SEMAPHORE_POOL:           {},
	nvgpu.UVM_SET_PREFERRED_LOCATION:         {},
	nvgpu.UVM_SET_ACCESSED_BY:                {},
	nvgpu.UVM_MIGRATE:                        {},
	nvgpu.UVM_MAP_DYNAMIC_PARALLELISM_REGION: {},
	nvgpu.UVM_REGISTER_CHANNEL:               {},
	nvgpu.UVM_PAGEABLE_MEM_ACCESS_ON_GPU:     {},
}
