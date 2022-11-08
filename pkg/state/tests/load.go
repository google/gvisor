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

// +stateify savable
type genericContainer struct {
	v any
}

// +stateify savable
type afterLoadStruct struct {
	v int `state:"nosave"`
}

func (a *afterLoadStruct) afterLoad() {
	a.v++
}

// +stateify savable
type valueLoadStruct struct {
	v int `state:".(int64)"`
}

func (v *valueLoadStruct) saveV() int64 {
	return int64(v.v) // Save as int64.
}

func (v *valueLoadStruct) loadV(value int64) {
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

func (b *badCycleStruct) afterLoad() {
	if b.b != b {
		// This is not executable, since AfterLoad requires that the
		// object and all dependencies are complete. This should cause
		// a deadlock error during load.
		panic("badCycleStruct.afterLoad called")
	}
}
