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

package ilist

import (
	"testing"
)

type testEntry struct {
	Entry
	value int
}

type direct struct {
	directEntry
	value int
}

func verifyEquality(t *testing.T, entries []testEntry, l *List) {
	t.Helper()

	i := 0
	for it := l.Front(); it != nil; it = it.Next() {
		e := it.(*testEntry)
		if e != &entries[i] {
			t.Errorf("Wrong entry at index %d", i)
			return
		}
		i++
	}

	if i != len(entries) {
		t.Errorf("Wrong number of entries; want = %d, got = %d", len(entries), i)
		return
	}

	i = 0
	for it := l.Back(); it != nil; it = it.Prev() {
		e := it.(*testEntry)
		if e != &entries[len(entries)-1-i] {
			t.Errorf("Wrong entry at index %d", i)
			return
		}
		i++
	}

	if i != len(entries) {
		t.Errorf("Wrong number of entries; want = %d, got = %d", len(entries), i)
		return
	}
}

func TestZeroEmpty(t *testing.T) {
	var l List
	if l.Front() != nil {
		t.Error("Front is non-nil")
	}
	if l.Back() != nil {
		t.Error("Back is non-nil")
	}
}

func TestPushBack(t *testing.T) {
	var l List

	// Test single entry insertion.
	var entry testEntry
	l.PushBack(&entry)

	e := l.Front().(*testEntry)
	if e != &entry {
		t.Error("Wrong entry returned")
	}

	// Test inserting 100 entries.
	l.Reset()
	var entries [100]testEntry
	for i := range entries {
		l.PushBack(&entries[i])
	}

	verifyEquality(t, entries[:], &l)
}

func TestPushFront(t *testing.T) {
	var l List

	// Test single entry insertion.
	var entry testEntry
	l.PushFront(&entry)

	e := l.Front().(*testEntry)
	if e != &entry {
		t.Error("Wrong entry returned")
	}

	// Test inserting 100 entries.
	l.Reset()
	var entries [100]testEntry
	for i := range entries {
		l.PushFront(&entries[len(entries)-1-i])
	}

	verifyEquality(t, entries[:], &l)
}

func TestRemove(t *testing.T) {
	// Remove entry from single-element list.
	var l List
	var entry testEntry
	l.PushBack(&entry)
	l.Remove(&entry)
	if l.Front() != nil {
		t.Error("List is empty")
	}

	var entries [100]testEntry

	// Remove single element from lists of lengths 2 to 101.
	for n := 1; n <= len(entries); n++ {
		for extra := 0; extra <= n; extra++ {
			l.Reset()
			for i := 0; i < n; i++ {
				if extra == i {
					l.PushBack(&entry)
				}
				l.PushBack(&entries[i])
			}
			if extra == n {
				l.PushBack(&entry)
			}

			l.Remove(&entry)
			verifyEquality(t, entries[:n], &l)
		}
	}
}

func TestReset(t *testing.T) {
	var l List

	// Resetting list of one element.
	l.PushBack(&testEntry{})
	if l.Front() == nil {
		t.Error("List is empty")
	}

	l.Reset()
	if l.Front() != nil {
		t.Error("List is not empty")
	}

	// Resetting list of 10 elements.
	for i := 0; i < 10; i++ {
		l.PushBack(&testEntry{})
	}

	if l.Front() == nil {
		t.Error("List is empty")
	}

	l.Reset()
	if l.Front() != nil {
		t.Error("List is not empty")
	}

	// Resetting empty list.
	l.Reset()
	if l.Front() != nil {
		t.Error("List is not empty")
	}
}

func TestRingAdd(t *testing.T) {
	e1 := &testEntry{value: 1}
	e2 := &testEntry{value: 2}
	e3 := &testEntry{value: 3}

	RingInit(e1)
	RingAdd(e1, e2)
	RingAdd(e1, e3)

	sum := 0
	for e := e1.Next(); e != e1; e = e.Next() {
		sum += e.(*testEntry).value
	}
	if sum != 5 {
		t.Errorf("wrong sum: want 5, got %d", sum)
	}
}

func TestRingRemove(t *testing.T) {
	e1 := &testEntry{value: 1}
	e2 := &testEntry{value: 2}
	e3 := &testEntry{value: 3}

	RingInit(e1)
	RingAdd(e1, e2)
	RingAdd(e2, e3)
	RingRemove(e2)

	sum := 0
	for e := e1.Next(); e != e1; e = e.Next() {
		sum += e.(*testEntry).value
	}
	if sum != 3 {
		t.Errorf("wrong sum: want 3, got %d", sum)
	}
}

func TestRingEmpty(t *testing.T) {
	e1 := &testEntry{value: 1}
	e2 := &testEntry{value: 2}
	e3 := &testEntry{value: 3}

	RingInit(e1)
	RingAdd(e1, e2)
	RingAdd(e2, e3)
	RingRemove(e3)
	RingRemove(e2)

	sum := 0
	for e := e1.Next(); e != e1; e = e.Next() {
		sum += e.(*testEntry).value
	}
	if sum != 0 {
		t.Errorf("wrong sum: want 0, got %d", sum)
	}
}

func BenchmarkIterateForward(b *testing.B) {
	var l List
	for i := 0; i < 1000000; i++ {
		l.PushBack(&testEntry{value: i})
	}

	for i := b.N; i > 0; i-- {
		tmp := 0
		for e := l.Front(); e != nil; e = e.Next() {
			tmp += e.(*testEntry).value
		}
	}
}

func BenchmarkIterateBackward(b *testing.B) {
	var l List
	for i := 0; i < 1000000; i++ {
		l.PushBack(&testEntry{value: i})
	}

	for i := b.N; i > 0; i-- {
		tmp := 0
		for e := l.Back(); e != nil; e = e.Prev() {
			tmp += e.(*testEntry).value
		}
	}
}

func BenchmarkDirectIterateForward(b *testing.B) {
	var l directList
	for i := 0; i < 1000000; i++ {
		l.PushBack(&direct{value: i})
	}

	for i := b.N; i > 0; i-- {
		tmp := 0
		for e := l.Front(); e != nil; e = e.Next() {
			tmp += e.value
		}
	}
}

func BenchmarkDirectIterateBackward(b *testing.B) {
	var l directList
	for i := 0; i < 1000000; i++ {
		l.PushBack(&direct{value: i})
	}

	for i := b.N; i > 0; i-- {
		tmp := 0
		for e := l.Back(); e != nil; e = e.Prev() {
			tmp += e.value
		}
	}
}
