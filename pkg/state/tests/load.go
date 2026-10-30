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

package tests

import (
	"context"

	"gvisor.dev/gvisor/pkg/state"
)

// +stateify savable
type genericContainer struct {
	v any
}

// +stateify savable
type afterLoadStruct struct {
	v int `state:"nosave"`
}

func (a *afterLoadStruct) afterLoad(context.Context) {
	a.v++
}

// +stateify savable
type valueLoadStruct struct {
	v int `state:".(int64)"`
}

func (v *valueLoadStruct) saveV() int64 {
	return int64(v.v) // Save as int64.
}

func (v *valueLoadStruct) loadV(_ context.Context, value int64) {
	v.v = int(value) // Load as int.
}

// +stateify savable
type cycleStruct struct {
	c *cycleStruct
}

// +stateify savable
type badCycleStruct struct {
	b *badCycleStruct `state:"wait"`
}

func (b *badCycleStruct) afterLoad(context.Context) {
	if b.b != b {
		// This is not executable, since AfterLoad requires that the
		// object and all dependencies are complete. This should cause
		// a deadlock error during load.
		panic("badCycleStruct.afterLoad called")
	}
}

// +stateify savable
type branchingCycle struct {
	reachable   *branchingCycle
	waitFor     *branchingCycle `state:"wait"`
	alsoWaitFor *branchingCycle `state:"wait"`
}

// +stateify savable
type sliceValueRes struct {
	name string
}

// +stateify savable
type sliceValueRef struct {
	target *valueLoadStruct
}

// +stateify savable
type sliceValueElem struct {
	res    string           `state:".(sliceValueRes)"`
	ref    *valueLoadStruct `state:".(sliceValueRef)"`
	ready  bool             `state:"nosave"`
	refSet bool             `state:"nosave"`
}

func (e *sliceValueElem) saveRes() sliceValueRes {
	if e.res == "" {
		state.Failf("sliceValueElem saved before loadRes ran")
	}
	return sliceValueRes{name: e.res}
}

func (e *sliceValueElem) loadRes(_ context.Context, r sliceValueRes) {
	e.res = r.name
	e.ready = true
}

func (e *sliceValueElem) saveRef() sliceValueRef {
	if e.ref == nil {
		state.Failf("sliceValueElem saved before loadRef ran")
	}
	return sliceValueRef{target: e.ref}
}

func (e *sliceValueElem) loadRef(_ context.Context, r sliceValueRef) {
	e.ref = r.target
	e.refSet = true
}

// +stateify savable
type sliceValueHolder struct {
	items []sliceValueElem `state:".([]sliceValueElem)"`
}

func (h *sliceValueHolder) saveItems() []sliceValueElem {
	return append([]sliceValueElem(nil), h.items...)
}

func (h *sliceValueHolder) loadItems(_ context.Context, items []sliceValueElem) {
	for _, it := range items {
		if !it.ready || !it.refSet {
			state.Failf("sliceValueHolder.loadItems ran before element LoadValue callbacks")
		}
	}
	h.items = append([]sliceValueElem(nil), items...)
}
