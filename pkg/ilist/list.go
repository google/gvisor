// Copyright 2018 Google Inc.
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

// Package ilist provides the implementation of intrusive linked lists.
package ilist

// Linker is the interface that objects must implement if they want to be added
// to and/or removed from List objects.
//
// N.B. When substituted in a template instantiation, Linker doesn't need to
// be an interface, and in most cases won't be.
type Linker interface {
	Next() Linker
	Prev() Linker
	SetNext(Linker)
	SetPrev(Linker)
}

// List is an intrusive list. Entries can be added to or removed from the list
// in O(1) time and with no additional memory allocations.
//
// The zero value for List is an empty list ready to use.
//
// To iterate over a list (where l is a List):
//      for e := l.Front(); e != nil; e = e.Next() {
// 		// do something with e.
//      }
//
// +stateify savable
type List struct {
	head Linker
	tail Linker
}

// Reset resets list l to the empty state.
func (l *List) Reset() {
	l.head = nil
	l.tail = nil
}

// Empty returns true iff the list is empty.
func (l *List) Empty() bool {
	return l.head == nil
}

// Front returns the first element of list l or nil.
func (l *List) Front() Linker {
	return l.head
}

// Back returns the last element of list l or nil.
func (l *List) Back() Linker {
	return l.tail
}

// PushFront inserts the element e at the front of list l.
func (l *List) PushFront(e Linker) {
	e.SetNext(l.head)
	e.SetPrev(nil)

	if l.head != nil {
		l.head.SetPrev(e)
	} else {
		l.tail = e
	}

	l.head = e
}

// PushBack inserts the element e at the back of list l.
func (l *List) PushBack(e Linker) {
	e.SetNext(nil)
	e.SetPrev(l.tail)

	if l.tail != nil {
		l.tail.SetNext(e)
	} else {
		l.head = e
	}

	l.tail = e
}

// PushBackList inserts list m at the end of list l, emptying m.
func (l *List) PushBackList(m *List) {
	if l.head == nil {
		l.head = m.head
		l.tail = m.tail
	} else if m.head != nil {
		l.tail.SetNext(m.head)
		m.head.SetPrev(l.tail)

		l.tail = m.tail
	}

	m.head = nil
	m.tail = nil
}

// InsertAfter inserts e after b.
func (l *List) InsertAfter(b, e Linker) {
	a := b.Next()
	e.SetNext(a)
	e.SetPrev(b)
	b.SetNext(e)

	if a != nil {
		a.SetPrev(e)
	} else {
		l.tail = e
	}
}

// InsertBefore inserts e before a.
func (l *List) InsertBefore(a, e Linker) {
	b := a.Prev()
	e.SetNext(a)
	e.SetPrev(b)
	a.SetPrev(e)

	if b != nil {
		b.SetNext(e)
	} else {
		l.head = e
	}
}

// Remove removes e from l.
func (l *List) Remove(e Linker) {
	prev := e.Prev()
	next := e.Next()

	if prev != nil {
		prev.SetNext(next)
	} else {
		l.head = next
	}

	if next != nil {
		next.SetPrev(prev)
	} else {
		l.tail = prev
	}
}

// Entry is a default implementation of Linker. Users can add anonymous fields
// of this type to their structs to make them automatically implement the
// methods needed by List.
//
// +stateify savable
type Entry struct {
	next Linker
	prev Linker
}

// Next returns the entry that follows e in the list.
func (e *Entry) Next() Linker {
	return e.next
}

// Prev returns the entry that precedes e in the list.
func (e *Entry) Prev() Linker {
	return e.prev
}

// SetNext assigns 'entry' as the entry that follows e in the list.
func (e *Entry) SetNext(entry Linker) {
	e.next = entry
}

// SetPrev assigns 'entry' as the entry that precedes e in the list.
func (e *Entry) SetPrev(entry Linker) {
	e.prev = entry
}
