// Copyright 2018 Google LLC
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
	Next() Element
	Prev() Element
	SetNext(Element)
	SetPrev(Element)
}

// Element the item that is used at the API level.
//
// N.B. Like Linker, this is unlikely to be an interface in most cases.
type Element interface {
	Linker
}

// ElementMapper provides an identity mapping by default.
//
// This can be replaced to provide a struct that maps elements to linker
// objects, if they are not the same. An ElementMapper is not typically
// required if: Linker is left as is, Element is left as is, or Linker and
// Element are the same type.
type ElementMapper struct{}

// linkerFor maps an Element to a Linker.
//
// This default implementation should be inlined.
//
//go:nosplit
func (ElementMapper) linkerFor(elem Element) Linker { return elem }

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
	head Element
	tail Element
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
func (l *List) Front() Element {
	return l.head
}

// Back returns the last element of list l or nil.
func (l *List) Back() Element {
	return l.tail
}

// PushFront inserts the element e at the front of list l.
func (l *List) PushFront(e Element) {
	ElementMapper{}.linkerFor(e).SetNext(l.head)
	ElementMapper{}.linkerFor(e).SetPrev(nil)

	if l.head != nil {
		ElementMapper{}.linkerFor(l.head).SetPrev(e)
	} else {
		l.tail = e
	}

	l.head = e
}

// PushBack inserts the element e at the back of list l.
func (l *List) PushBack(e Element) {
	ElementMapper{}.linkerFor(e).SetNext(nil)
	ElementMapper{}.linkerFor(e).SetPrev(l.tail)

	if l.tail != nil {
		ElementMapper{}.linkerFor(l.tail).SetNext(e)
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
		ElementMapper{}.linkerFor(l.tail).SetNext(m.head)
		ElementMapper{}.linkerFor(m.head).SetPrev(l.tail)

		l.tail = m.tail
	}

	m.head = nil
	m.tail = nil
}

// InsertAfter inserts e after b.
func (l *List) InsertAfter(b, e Element) {
	a := ElementMapper{}.linkerFor(b).Next()
	ElementMapper{}.linkerFor(e).SetNext(a)
	ElementMapper{}.linkerFor(e).SetPrev(b)
	ElementMapper{}.linkerFor(b).SetNext(e)

	if a != nil {
		ElementMapper{}.linkerFor(a).SetPrev(e)
	} else {
		l.tail = e
	}
}

// InsertBefore inserts e before a.
func (l *List) InsertBefore(a, e Element) {
	b := ElementMapper{}.linkerFor(a).Prev()
	ElementMapper{}.linkerFor(e).SetNext(a)
	ElementMapper{}.linkerFor(e).SetPrev(b)
	ElementMapper{}.linkerFor(a).SetPrev(e)

	if b != nil {
		ElementMapper{}.linkerFor(b).SetNext(e)
	} else {
		l.head = e
	}
}

// Remove removes e from l.
func (l *List) Remove(e Element) {
	prev := ElementMapper{}.linkerFor(e).Prev()
	next := ElementMapper{}.linkerFor(e).Next()

	if prev != nil {
		ElementMapper{}.linkerFor(prev).SetNext(next)
	} else {
		l.head = next
	}

	if next != nil {
		ElementMapper{}.linkerFor(next).SetPrev(prev)
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
	next Element
	prev Element
}

// Next returns the entry that follows e in the list.
func (e *Entry) Next() Element {
	return e.next
}

// Prev returns the entry that precedes e in the list.
func (e *Entry) Prev() Element {
	return e.prev
}

// SetNext assigns 'entry' as the entry that follows e in the list.
func (e *Entry) SetNext(elem Element) {
	e.next = elem
}

// SetPrev assigns 'entry' as the entry that precedes e in the list.
func (e *Entry) SetPrev(elem Element) {
	e.prev = elem
}
