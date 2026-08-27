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

package semaphore

import (
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/kernel/ipc"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
)

func executeOps(ctx context.Context, t *testing.T, set *Set, ops []linux.Sembuf, block bool) chan struct{} {
	set.mu.Lock()
	ch, _, err := set.executeOps(ctx, ops, 123)
	set.mu.Unlock()
	if err != nil {
		t.Fatalf("ExecuteOps(ops) failed, err: %v, ops: %+v", err, ops)
	}
	if block {
		if ch == nil {
			t.Fatalf("ExecuteOps(ops) got: nil, expected: !nil, ops: %+v", ops)
		}
		if signalled(ch) {
			t.Fatalf("ExecuteOps(ops) channel should not have been signalled, ops: %+v", ops)
		}
	} else {
		if ch != nil {
			t.Fatalf("ExecuteOps(ops) got: %v, expected: nil, ops: %+v", ch, ops)
		}
	}
	return ch
}

func signalled(ch chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

func TestBasic(t *testing.T) {
	ctx := contexttest.Context(t)
	set := &Set{obj: &ipc.Object{ID: 123}, sems: make([]sem, 1)}
	ops := []linux.Sembuf{
		{SemOp: 1},
	}
	executeOps(ctx, t, set, ops, false)

	ops[0].SemOp = -1
	executeOps(ctx, t, set, ops, false)

	ops[0].SemOp = -1
	ch1 := executeOps(ctx, t, set, ops, true)

	ops[0].SemOp = 1
	executeOps(ctx, t, set, ops, false)
	if !signalled(ch1) {
		t.Fatalf("ExecuteOps(ops) channel should not have been signalled, ops: %+v", ops)
	}
}

func TestWaitForZero(t *testing.T) {
	ctx := contexttest.Context(t)
	set := &Set{obj: &ipc.Object{ID: 123}, sems: make([]sem, 1)}
	ops := []linux.Sembuf{
		{SemOp: 0},
	}
	executeOps(ctx, t, set, ops, false)

	ops[0].SemOp = -2
	ch1 := executeOps(ctx, t, set, ops, true)

	ops[0].SemOp = 0
	executeOps(ctx, t, set, ops, false)

	ops[0].SemOp = 1
	executeOps(ctx, t, set, ops, false)

	ops[0].SemOp = 0
	chZero1 := executeOps(ctx, t, set, ops, true)

	ops[0].SemOp = 0
	chZero2 := executeOps(ctx, t, set, ops, true)

	ops[0].SemOp = 1
	executeOps(ctx, t, set, ops, false)
	if !signalled(ch1) {
		t.Fatalf("ExecuteOps(ops) channel should have been signalled, ops: %+v, set: %+v", ops, set)
	}

	ops[0].SemOp = -2
	executeOps(ctx, t, set, ops, false)
	if !signalled(chZero1) {
		t.Fatalf("ExecuteOps(ops) channel zero 1 should have been signalled, ops: %+v, set: %+v", ops, set)
	}
	if !signalled(chZero2) {
		t.Fatalf("ExecuteOps(ops) channel zero 2 should have been signalled, ops: %+v, set: %+v", ops, set)
	}
}

func TestNoWait(t *testing.T) {
	ctx := contexttest.Context(t)
	set := &Set{obj: &ipc.Object{ID: 123}, sems: make([]sem, 1)}
	ops := []linux.Sembuf{
		{SemOp: 1},
	}
	executeOps(ctx, t, set, ops, false)

	ops[0].SemOp = -2
	ops[0].SemFlg = linux.IPC_NOWAIT
	set.mu.Lock()
	defer set.mu.Unlock()
	if _, _, err := set.executeOps(ctx, ops, 123); err != linuxerr.ErrWouldBlock {
		t.Fatalf("ExecuteOps(ops) wrong result, got: %v, expected: %v", err, linuxerr.ErrWouldBlock)
	}

	ops[0].SemOp = 0
	ops[0].SemFlg = linux.IPC_NOWAIT
	if _, _, err := set.executeOps(ctx, ops, 123); err != linuxerr.ErrWouldBlock {
		t.Fatalf("ExecuteOps(ops) wrong result, got: %v, expected: %v", err, linuxerr.ErrWouldBlock)
	}
}

func TestUnregister(t *testing.T) {
	ctx := contexttest.Context(t)
	defer pgalloc.MemoryFileFromContext(ctx).Destroy()
	creds := auth.CredentialsFromContext(ctx)
	r := NewRegistry(creds.UserNamespace)
	set, err := r.FindOrCreate(ctx, 123, 2, 0600, true, true, true)

	if err != nil {
		t.Fatalf("FindOrCreate() failed, err: %v", err)
	}
	if got := r.FindByID(set.obj.ID); got != set {
		t.Fatalf("FindById(%d) failed, got: %+v, expected: %+v", set.obj.ID, got, set)
	}
	index := r.HighestIndex()

	ops := []linux.Sembuf{
		{SemOp: -1},
	}
	chs := make([]chan struct{}, 0, 5)
	for i := 0; i < 5; i++ {
		ch := executeOps(ctx, t, set, ops, true)
		chs = append(chs, ch)
	}

	// contexttest supplies UID 65534. UID 1 is not the owner and has no
	// effective capabilities.
	other := auth.NewUserCredentials(1, 1, nil, nil, creds.UserNamespace)
	if err := r.Remove(set.obj.ID, other); err != linuxerr.EPERM {
		t.Errorf("Remove by non-owner = %v, want EPERM", err)
	}
	if got := r.FindByID(set.obj.ID); got != set {
		t.Fatalf("FindByID after denied removal = %p, want %p", got, set)
	}
	if got := r.FindByIndex(index); got != set {
		t.Errorf("FindByIndex after denied removal = %p, want %p", got, set)
	}
	if ch, _, err := set.ExecuteOps(ctx, []linux.Sembuf{{SemOp: 0}}, creds, 123); err != nil || ch != nil {
		t.Fatalf("ExecuteOps after denied removal = (%v, %v), want (nil, nil)", ch, err)
	}
	for i, ch := range chs {
		if signalled(ch) {
			t.Errorf("channel %d was signalled after denied removal", i)
		}
	}

	if err := r.Remove(set.obj.ID, creds); err != nil {
		t.Fatalf("Remove(%d) failed, err: %v", set.obj.ID, err)
	}
	set.mu.Lock()
	dead := set.dead
	set.mu.Unlock()
	if !dead {
		t.Fatalf("set is not dead: %+v", set)
	}
	if got := r.FindByID(set.obj.ID); got != nil {
		t.Fatalf("FindById(%d) failed, got: %+v, expected: nil", set.obj.ID, got)
	}
	for i, ch := range chs {
		if !signalled(ch) {
			t.Fatalf("channel %d should have been signalled", i)
		}
	}
}
