package stack

// ElementMapper provides an identity mapping by default.
//
// This can be replaced to provide a struct that maps elements to linker
// objects, if they are not the same. An ElementMapper is not typically
// required if: Linker is left as is, Element is left as is, or Linker and
// Element are the same type.
type linkAddrEntryElementMapper struct{}

// linkerFor maps an Element to a Linker.
//
// This default implementation should be inlined.
//
//go:nosplit
func (linkAddrEntryElementMapper) linkerFor(elem *linkAddrEntry) *linkAddrEntry { return elem }

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
type linkAddrEntryList struct {
	head *linkAddrEntry
	tail *linkAddrEntry
}

// Reset resets list l to the empty state.
func (l *linkAddrEntryList) Reset() {
	l.head = nil
	l.tail = nil
}

// Empty returns true iff the list is empty.
func (l *linkAddrEntryList) Empty() bool {
	return l.head == nil
}

// Front returns the first element of list l or nil.
func (l *linkAddrEntryList) Front() *linkAddrEntry {
	return l.head
}

// Back returns the last element of list l or nil.
func (l *linkAddrEntryList) Back() *linkAddrEntry {
	return l.tail
}

// PushFront inserts the element e at the front of list l.
func (l *linkAddrEntryList) PushFront(e *linkAddrEntry) {
	linkAddrEntryElementMapper{}.linkerFor(e).SetNext(l.head)
	linkAddrEntryElementMapper{}.linkerFor(e).SetPrev(nil)

	if l.head != nil {
		linkAddrEntryElementMapper{}.linkerFor(l.head).SetPrev(e)
	} else {
		l.tail = e
	}

	l.head = e
}

// PushBack inserts the element e at the back of list l.
func (l *linkAddrEntryList) PushBack(e *linkAddrEntry) {
	linkAddrEntryElementMapper{}.linkerFor(e).SetNext(nil)
	linkAddrEntryElementMapper{}.linkerFor(e).SetPrev(l.tail)

	if l.tail != nil {
		linkAddrEntryElementMapper{}.linkerFor(l.tail).SetNext(e)
	} else {
		l.head = e
	}

	l.tail = e
}

// PushBackList inserts list m at the end of list l, emptying m.
func (l *linkAddrEntryList) PushBackList(m *linkAddrEntryList) {
	if l.head == nil {
		l.head = m.head
		l.tail = m.tail
	} else if m.head != nil {
		linkAddrEntryElementMapper{}.linkerFor(l.tail).SetNext(m.head)
		linkAddrEntryElementMapper{}.linkerFor(m.head).SetPrev(l.tail)

		l.tail = m.tail
	}

	m.head = nil
	m.tail = nil
}

// InsertAfter inserts e after b.
func (l *linkAddrEntryList) InsertAfter(b, e *linkAddrEntry) {
	a := linkAddrEntryElementMapper{}.linkerFor(b).Next()
	linkAddrEntryElementMapper{}.linkerFor(e).SetNext(a)
	linkAddrEntryElementMapper{}.linkerFor(e).SetPrev(b)
	linkAddrEntryElementMapper{}.linkerFor(b).SetNext(e)

	if a != nil {
		linkAddrEntryElementMapper{}.linkerFor(a).SetPrev(e)
	} else {
		l.tail = e
	}
}

// InsertBefore inserts e before a.
func (l *linkAddrEntryList) InsertBefore(a, e *linkAddrEntry) {
	b := linkAddrEntryElementMapper{}.linkerFor(a).Prev()
	linkAddrEntryElementMapper{}.linkerFor(e).SetNext(a)
	linkAddrEntryElementMapper{}.linkerFor(e).SetPrev(b)
	linkAddrEntryElementMapper{}.linkerFor(a).SetPrev(e)

	if b != nil {
		linkAddrEntryElementMapper{}.linkerFor(b).SetNext(e)
	} else {
		l.head = e
	}
}

// Remove removes e from l.
func (l *linkAddrEntryList) Remove(e *linkAddrEntry) {
	prev := linkAddrEntryElementMapper{}.linkerFor(e).Prev()
	next := linkAddrEntryElementMapper{}.linkerFor(e).Next()

	if prev != nil {
		linkAddrEntryElementMapper{}.linkerFor(prev).SetNext(next)
	} else {
		l.head = next
	}

	if next != nil {
		linkAddrEntryElementMapper{}.linkerFor(next).SetPrev(prev)
	} else {
		l.tail = prev
	}
}

// Entry is a default implementation of Linker. Users can add anonymous fields
// of this type to their structs to make them automatically implement the
// methods needed by List.
//
// +stateify savable
type linkAddrEntryEntry struct {
	next *linkAddrEntry
	prev *linkAddrEntry
}

// Next returns the entry that follows e in the list.
func (e *linkAddrEntryEntry) Next() *linkAddrEntry {
	return e.next
}

// Prev returns the entry that precedes e in the list.
func (e *linkAddrEntryEntry) Prev() *linkAddrEntry {
	return e.prev
}

// SetNext assigns 'entry' as the entry that follows e in the list.
func (e *linkAddrEntryEntry) SetNext(elem *linkAddrEntry) {
	e.next = elem
}

// SetPrev assigns 'entry' as the entry that precedes e in the list.
func (e *linkAddrEntryEntry) SetPrev(elem *linkAddrEntry) {
	e.prev = elem
}
