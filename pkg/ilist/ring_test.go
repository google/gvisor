// Copyright 2023 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ring

import (
	"testing"
)

type testContainer struct {
	value int
	entry testEntry
}

func newContainer(value int) *testContainer {
	c := &testContainer{value: value}
	c.entry.Init(c)
	return c
}

func TestAdd(t *testing.T) {
	e1 := newContainer(1)
	e2 := newContainer(2)
	e3 := newContainer(3)

	e1.entry.Add(&e2.entry)
	e1.entry.Add(&e3.entry)

	sum := 0
	want := 6
	e := e1
	for {
		sum += e.value
		e = e.entry.Next()
		if e == e1 {
			break
		}
	}
	if sum != want {
		t.Errorf("wrong sum: want %d, got %d", want, sum)
	}
}

func TestRemove(t *testing.T) {
	e1 := newContainer(1)
	e2 := newContainer(2)
	e3 := newContainer(3)

	e1.entry.Add(&e2.entry)
	e2.entry.Add(&e3.entry)
	e2.entry.Remove()

	sum := 0
	want := 4
	e := e1
	for {
		sum += e.value
		e = e.entry.Next()
		if e == e1 {
			break
		}
	}
	if sum != want {
		t.Errorf("wrong sum: want %d, got %d", want, sum)
	}
}

func TestEmpty(t *testing.T) {
	head := newContainer(1)
	e2 := newContainer(2)
	e3 := newContainer(3)

	head.entry.Add(&e2.entry)
	e2.entry.Add(&e3.entry)
	e3.entry.Remove()
	e2.entry.Remove()

	sum := 0
	want := 0
	for e := head.entry.Next(); e != head; e = e.entry.Next() {
		sum += e.value
	}
	if sum != want {
		t.Errorf("wrong sum: want %d, got %d", want, sum)
	}
}
