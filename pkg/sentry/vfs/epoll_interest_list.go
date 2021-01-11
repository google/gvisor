package vfs

// ElementMapper provides an identity mapping by default.
//
// This can be replaced to provide a struct that maps elements to linker
// objects, if they are not the same. An ElementMapper is not typically
// required if: Linker is left as is, Element is left as is, or Linker and
// Element are the same type.
type epollInterestElementMapper struct{}

// linkerFor maps an Element to a Linker.
//
// This default implementation should be inlined.
//
//go:nosplit
func (epollInterestElementMapper) linkerFor(elem *epollInterest) *epollInterest { return elem }

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
type epollInterestList struct {
	head *epollInterest
	tail *epollInterest
}

// Reset resets list l to the empty state.
func (l *epollInterestList) Reset() {
	l.head = nil
	l.tail = nil
}

// Empty returns true iff the list is empty.
//
//go:nosplit
func (l *epollInterestList) Empty() bool {
	return l.head == nil
}

// Front returns the first element of list l or nil.
//
//go:nosplit
func (l *epollInterestList) Front() *epollInterest {
	return l.head
}

// Back returns the last element of list l or nil.
//
//go:nosplit
func (l *epollInterestList) Back() *epollInterest {
	return l.tail
}

// Len returns the number of elements in the list.
//
// NOTE: This is an O(n) operation.
//
//go:nosplit
func (l *epollInterestList) Len() (count int) {
	for e := l.Front(); e != nil; e = (epollInterestElementMapper{}.linkerFor(e)).Next() {
		count++
	}
	return count
}

// PushFront inserts the element e at the front of list l.
//
//go:nosplit
func (l *epollInterestList) PushFront(e *epollInterest) {
	linker := epollInterestElementMapper{}.linkerFor(e)
	linker.SetNext(l.head)
	linker.SetPrev(nil)
	if l.head != nil {
		epollInterestElementMapper{}.linkerFor(l.head).SetPrev(e)
	} else {
		l.tail = e
	}

	l.head = e
}

// PushBack inserts the element e at the back of list l.
//
//go:nosplit
func (l *epollInterestList) PushBack(e *epollInterest) {
	linker := epollInterestElementMapper{}.linkerFor(e)
	linker.SetNext(nil)
	linker.SetPrev(l.tail)
	if l.tail != nil {
		epollInterestElementMapper{}.linkerFor(l.tail).SetNext(e)
	} else {
		l.head = e
	}

	l.tail = e
}

// PushBackList inserts list m at the end of list l, emptying m.
//
//go:nosplit
func (l *epollInterestList) PushBackList(m *epollInterestList) {
	if l.head == nil {
		l.head = m.head
		l.tail = m.tail
	} else if m.head != nil {
		epollInterestElementMapper{}.linkerFor(l.tail).SetNext(m.head)
		epollInterestElementMapper{}.linkerFor(m.head).SetPrev(l.tail)

		l.tail = m.tail
	}
	m.head = nil
	m.tail = nil
}

// InsertAfter inserts e after b.
//
//go:nosplit
func (l *epollInterestList) InsertAfter(b, e *epollInterest) {
	bLinker := epollInterestElementMapper{}.linkerFor(b)
	eLinker := epollInterestElementMapper{}.linkerFor(e)

	a := bLinker.Next()

	eLinker.SetNext(a)
	eLinker.SetPrev(b)
	bLinker.SetNext(e)

	if a != nil {
		epollInterestElementMapper{}.linkerFor(a).SetPrev(e)
	} else {
		l.tail = e
	}
}

// InsertBefore inserts e before a.
//
//go:nosplit
func (l *epollInterestList) InsertBefore(a, e *epollInterest) {
	aLinker := epollInterestElementMapper{}.linkerFor(a)
	eLinker := epollInterestElementMapper{}.linkerFor(e)

	b := aLinker.Prev()
	eLinker.SetNext(a)
	eLinker.SetPrev(b)
	aLinker.SetPrev(e)

	if b != nil {
		epollInterestElementMapper{}.linkerFor(b).SetNext(e)
	} else {
		l.head = e
	}
}

// Remove removes e from l.
//
//go:nosplit
func (l *epollInterestList) Remove(e *epollInterest) {
	linker := epollInterestElementMapper{}.linkerFor(e)
	prev := linker.Prev()
	next := linker.Next()

	if prev != nil {
		epollInterestElementMapper{}.linkerFor(prev).SetNext(next)
	} else if l.head == e {
		l.head = next
	}

	if next != nil {
		epollInterestElementMapper{}.linkerFor(next).SetPrev(prev)
	} else if l.tail == e {
		l.tail = prev
	}

	linker.SetNext(nil)
	linker.SetPrev(nil)
}

// Entry is a default implementation of Linker. Users can add anonymous fields
// of this type to their structs to make them automatically implement the
// methods needed by List.
//
// +stateify savable
type epollInterestEntry struct {
	next *epollInterest
	prev *epollInterest
}

// Next returns the entry that follows e in the list.
//
//go:nosplit
func (e *epollInterestEntry) Next() *epollInterest {
	return e.next
}

// Prev returns the entry that precedes e in the list.
//
//go:nosplit
func (e *epollInterestEntry) Prev() *epollInterest {
	return e.prev
}

// SetNext assigns 'entry' as the entry that follows e in the list.
//
//go:nosplit
func (e *epollInterestEntry) SetNext(elem *epollInterest) {
	e.next = elem
}

// SetPrev assigns 'entry' as the entry that precedes e in the list.
//
//go:nosplit
func (e *epollInterestEntry) SetPrev(elem *epollInterest) {
	e.prev = elem
}
