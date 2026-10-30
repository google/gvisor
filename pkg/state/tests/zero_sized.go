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

package tests

import (
	"context"
)

// +stateify savable
type zeroCrossRoot struct {
	emptyA     *savableEmptyStruct
	emptyB     *zeroSizedOther
	nested     *zeroSizedNested
	anon       *struct{}
	ifaceA     any
	ifaceB     any
	emptyInts  []int64
	emptyStrs  []string
	zeroElems  []savableEmptyStruct
	anonElems  []struct{}
	checkValue int64
}

type zeroHookRecorderKey struct{}

type zeroHookRecorder struct {
	wantVal    int64
	gotVal     int64
	events     []string
	targetDone bool
}

// zeroHookTarget is a zero-sized savable struct (unsafe.Sizeof == 0) that has
// both a virtual value field and beforeSave/afterLoad hooks.
//
// +stateify savable
type zeroHookTarget struct {
	v    struct{} `state:".(int64)"`
	self struct{} `state:".(*zeroHookTarget)"`
}

func (z *zeroHookTarget) beforeSave() {}

func (z *zeroHookTarget) saveV() int64 {
	return 777
}

func (z *zeroHookTarget) loadV(ctx context.Context, v int64) {
	if rec, ok := ctx.Value(zeroHookRecorderKey{}).(*zeroHookRecorder); ok {
		rec.gotVal = v
		rec.events = append(rec.events, "target:loadV")
	}
}

func (z *zeroHookTarget) saveSelf() *zeroHookTarget {
	return z
}

func (z *zeroHookTarget) loadSelf(ctx context.Context, self *zeroHookTarget) {
	if self == nil {
		panic("zeroHookTarget.loadSelf got nil self pointer")
	}
	if rec, ok := ctx.Value(zeroHookRecorderKey{}).(*zeroHookRecorder); ok {
		rec.events = append(rec.events, "target:loadSelf")
	}
}

func (z *zeroHookTarget) afterLoad(ctx context.Context) {
	if rec, ok := ctx.Value(zeroHookRecorderKey{}).(*zeroHookRecorder); ok {
		rec.targetDone = true
		rec.events = append(rec.events, "target:afterLoad")
	}
}

// +stateify savable
type zeroHookWaiter struct {
	dep   *zeroHookTarget `state:"wait"`
	iface any
	id    int64
}

func (w *zeroHookWaiter) afterLoad(ctx context.Context) {
	if w.dep == nil {
		panic("zeroHookWaiter.dep is nil in afterLoad")
	}
	if rec, ok := ctx.Value(zeroHookRecorderKey{}).(*zeroHookRecorder); ok {
		if !rec.targetDone {
			panic("zeroHookWaiter.afterLoad ran before zeroHookTarget.afterLoad")
		}
		rec.events = append(rec.events, "waiter:afterLoad")
	}
}
