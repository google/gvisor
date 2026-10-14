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
	"encoding/binary"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/nvgpu"
	"gvisor.dev/gvisor/pkg/context"
)

// TestProcFDInfoExtra pins the fdinfo line, which userspace parses.
func TestProcFDInfoExtra(t *testing.T) {
	ctx := context.Background()
	fd := &frontendFD{}
	if got := fd.ProcFDInfoExtra(ctx); got != "" {
		t.Errorf("ProcFDInfoExtra() without an export = %q, want empty", got)
	}
	fd.exported = exportedObject{id: 7, client: nvgpu.Handle{Val: 0xc1d00922}, object: nvgpu.Handle{Val: 0x5c000123}}
	want := "nvproxy_exported_object:\tclient=0xc1d00922 object=0x5c000123 id=7\n"
	if got := fd.ProcFDInfoExtra(ctx); got != want {
		t.Errorf("ProcFDInfoExtra() = %q, want %q", got, want)
	}
}

func TestObjectExported(t *testing.T) {
	var single nvgpu.NV0000_CTRL_OS_UNIX_EXPORT_OBJECT_TO_FD_PARAMS
	single.Object.Type = nvgpu.NV0000_CTRL_OS_UNIX_EXPORT_OBJECT_TYPE_RM
	binary.LittleEndian.PutUint32(single.Object.Data[8:], 0x5c000001)
	if h, ok := objectExported(&single); !ok || h.Val != 0x5c000001 {
		t.Errorf("objectExported() = %v, %v, want 0x5c000001, true", h, ok)
	}
	single.Flags = nvgpu.NV0000_CTRL_OS_UNIX_EXPORT_OBJECT_TO_FD_FLAGS_EMPTY_FD
	if _, ok := objectExported(&single); ok {
		t.Errorf("objectExported() with EMPTY_FD = _, true, want false")
	}

	batch := nvgpu.NV0000_CTRL_OS_UNIX_EXPORT_OBJECTS_TO_FD_PARAMS{NumObjects: 2}
	batch.Objects[0] = nvgpu.Handle{Val: 0x5c000002}
	if h, ok := objectsExported(&batch); !ok || h.Val != 0x5c000002 {
		t.Errorf("objectsExported() = %v, %v, want 0x5c000002, true", h, ok)
	}
	batch.Index = 1
	if _, ok := objectsExported(&batch); ok {
		t.Errorf("objectsExported() past slot 0 = _, true, want false")
	}
}
