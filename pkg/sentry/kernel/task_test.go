// Copyright 2018 The gVisor Authors.
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

package kernel

import (
	"math"
	"testing"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/checkpoint"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/kernel/sched"
	"gvisor.dev/gvisor/pkg/sentry/limits"
	"gvisor.dev/gvisor/pkg/sentry/mm"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	"gvisor.dev/gvisor/pkg/usermem"
)

func TestTaskCPU(t *testing.T) {
	for _, test := range []struct {
		mask sched.CPUSet
		tid  ThreadID
		cpu  int32
	}{
		{
			mask: []byte{0xff},
			tid:  1,
			cpu:  1,
		},
		{
			mask: []byte{0xff},
			tid:  10,
			cpu:  2,
		},
		{
			// more than 8 cpus.
			mask: []byte{0xff, 0xff},
			tid:  10,
			cpu:  10,
		},
		{
			// missing the first cpu.
			mask: []byte{0xfe},
			tid:  1,
			cpu:  2,
		},
		{
			mask: []byte{0xfe},
			tid:  10,
			cpu:  4,
		},
		{
			// missing the fifth cpu.
			mask: []byte{0xef},
			tid:  10,
			cpu:  3,
		},
		{
			// only the fifth cpu.
			mask: []byte{0x10},
			tid:  10,
			cpu:  4,
		},
	} {
		assigned := assignCPU(test.mask, test.tid)
		if test.cpu != assigned {
			t.Errorf("assignCPU(%v, %v) got %v, want %v", test.mask, test.tid, assigned, test.cpu)
		}
	}
}

func TestFSCheckpointedMemoryFilesFromContext(t *testing.T) {
	if got := FSCheckpointedMemoryFilesFromContext(nil); got != nil {
		t.Errorf("FSCheckpointedMemoryFilesFromContext(nil) = %v, want nil", got)
	}
	ctx := context.Background()
	if got := FSCheckpointedMemoryFilesFromContext(ctx); got != nil {
		t.Errorf("FSCheckpointedMemoryFilesFromContext(ctx) = %v, want nil", got)
	}
	mfs := make(map[checkpoint.ResourceID]struct{})
	ctx = WithFSRestore(ctx, mfs)
	if got := FSCheckpointedMemoryFilesFromContext(ctx); got == nil {
		t.Errorf("FSCheckpointedMemoryFilesFromContext(ctx) = nil, want non-nil")
	}
}

func TestMatchesPaths(t *testing.T) {
	pathsMap := map[checkpoint.ResourceID]struct{}{
		{ContainerName: "c1", Path: "/data"}: {},
	}
	rid := checkpoint.ResourceID{ContainerName: "c1", Path: "/data"}
	if !matchesPaths(rid, pathsMap, true /* isTmpfs */) {
		t.Errorf("matchesPaths(%+v, isTmpfs=true) = false, want true", rid)
	}
	if matchesPaths(rid, pathsMap, false /* isTmpfs */) {
		t.Errorf("matchesPaths(%+v, isTmpfs=false) = true, want false", rid)
	}
}

func TestMatchesPathsDefaultRoot(t *testing.T) {
	pathsMap := map[checkpoint.ResourceID]struct{}{
		{Path: "/"}: {},
	}
	rid := checkpoint.ResourceID{Path: "/"}
	if !matchesPaths(rid, pathsMap, true /* isTmpfs */) {
		t.Errorf("matchesPaths(%+v, isTmpfs=true) = false, want true", rid)
	}
}

func TestPIDNamespaceLastTID(t *testing.T) {
	ns := newTaskSet(NewRootPIDNamespace(nil)).Root
	if got := ns.LastTID(); got != 0 {
		t.Errorf("ns.LastTID() = %d, want 0", got)
	}
	ns.ReserveInitTID()
	if got := ns.LastTID(); got != initTID {
		t.Errorf("ns.LastTID() = %d, want %d", got, initTID)
	}
	ns.owner.mu.Lock()
	tid, err := ns.allocateTID()
	ns.owner.mu.Unlock()
	if err != nil {
		t.Fatalf("ns.allocateTID() failed: %v", err)
	}
	if got := ns.LastTID(); got != tid {
		t.Errorf("ns.LastTID() = %d, want %d", got, tid)
	}
}

func TestIovecImportValidatesCopiedPrefixBeforeFault(t *testing.T) {
	task := &Task{image: TaskImage{
		Arch:          &arch.Context64{},
		MemoryManager: &mm.MemoryManager{},
	}}
	for _, tc := range []struct {
		name   string
		length uint64
		want   error
	}{
		{"invalid-prefix", math.MaxUint64, linuxerr.EINVAL},
		{"valid-prefix", 0, linuxerr.EFAULT},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Only the first descriptor and half of the second are readable.
			metadata := make([]byte, 24)
			hostarch.ByteOrder.PutUint64(metadata[8:16], tc.length)
			ctx := &usermem.IOCopyContext{
				Ctx: context.Background(),
				IO:  &usermem.BytesIO{Bytes: metadata},
			}
			got, err := copyInIovecs(ctx, task, 0, 2)
			if err != tc.want || len(got) != 0 {
				t.Fatalf("iovec import = (%v, %v), want empty result and %v", got, err, tc.want)
			}
		})
	}
}

type iovecCopyErrorContext struct {
	usermem.IOCopyContext
	errorAboveSize int
}

func (ctx *iovecCopyErrorContext) CopyInBytes(addr hostarch.Addr, dst []byte) (int, error) {
	n, err := ctx.IOCopyContext.CopyInBytes(addr, dst)
	if err != nil {
		return n, err
	}
	if len(dst) > ctx.errorAboveSize {
		return n, linuxerr.EFAULT
	}
	return n, nil
}

func TestIovecImportCopyErrorPrecedesLengthValidation(t *testing.T) {
	task := &Task{image: TaskImage{Arch: &arch.Context64{}}}
	for _, tc := range []struct {
		name  string
		addr  hostarch.Addr
		count int
	}{
		{"single-entry", 0, 1},
		{"multiple-entries", 0, 2},
		{"straddling-entry", hostarch.PageSize - 8, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			metadata := make([]byte, int(tc.addr)+tc.count*16)
			hostarch.ByteOrder.PutUint64(metadata[int(tc.addr)+8:], math.MaxUint64)
			ctx := &iovecCopyErrorContext{IOCopyContext: usermem.IOCopyContext{
				Ctx: context.Background(),
				IO:  &usermem.BytesIO{Bytes: metadata},
			}}
			got, err := copyInIovecs(ctx, task, tc.addr, tc.count)
			if err != linuxerr.EFAULT || len(got) != 0 {
				t.Fatalf("iovec import = (%v, %v), want empty result and EFAULT", got, err)
			}
		})
	}
}

func TestIovecImportSucceedsAfterBatchCopyError(t *testing.T) {
	testCtx := contexttest.Context(t)
	memoryManager, err := mm.NewMemoryManager(
		platform.FromContext(testCtx), pgalloc.MemoryFileFromContext(testCtx))
	if err != nil {
		t.Fatalf("mm.NewMemoryManager failed: %v", err)
	}
	defer memoryManager.DecUsers(testCtx)
	archContext := &arch.Context64{}
	if _, err := memoryManager.SetMmapLayout(archContext, limits.NewLimitSet()); err != nil {
		t.Fatalf("MemoryManager.SetMmapLayout failed: %v", err)
	}
	task := &Task{image: TaskImage{
		Arch:          archContext,
		MemoryManager: memoryManager,
	}}
	metadata := make([]byte, 32)
	hostarch.ByteOrder.PutUint64(metadata[0:8], 0x1000)
	hostarch.ByteOrder.PutUint64(metadata[8:16], 0x100)
	hostarch.ByteOrder.PutUint64(metadata[16:24], 0x3000)
	hostarch.ByteOrder.PutUint64(metadata[24:32], 0x200)
	ctx := &iovecCopyErrorContext{
		IOCopyContext: usermem.IOCopyContext{
			Ctx: testCtx,
			IO:  &usermem.BytesIO{Bytes: metadata},
		},
		errorAboveSize: 16,
	}
	got, err := copyInIovecs(ctx, task, 0, 2)
	if err != nil {
		t.Fatalf("copyInIovecs failed: %v", err)
	}
	want := []hostarch.AddrRange{
		{Start: 0x1000, End: 0x1100},
		{Start: 0x3000, End: 0x3200},
	}
	if len(got) != len(want) {
		t.Fatalf("copyInIovecs returned %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("iovec range %d = %v, want %v", i, got[i], want[i])
		}
	}
}
