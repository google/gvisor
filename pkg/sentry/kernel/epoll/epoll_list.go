package epoll

// ElementMapper provides an identity mapping by default.
//
// This can be replaced to provide a struct that maps elements to linker
// objects, if they are not the same. An ElementMapper is not typically
// required if: Linker is left as is, Element is left as is, or Linker and
// Element are the same type.
type pollEntryElementMapper struct{}

// linkerFor maps an Element to a Linker.
//
// This default implementation should be inlined.
//
//go:nosplit
func (pollEntryElementMapper) linkerFor(elem *pollEntry) *pollEntry { return elem }

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
type pollEntryList struct {
	head *pollEntry
	tail *pollEntry
}

// Reset resets list l to the empty state.
func (l *pollEntryList) Reset() {
	l.head = nil
	l.tail = nil
}

// Empty returns true iff the list is empty.
func (l *pollEntryList) Empty() bool {
	return l.head == nil
}

// Front returns the first element of list l or nil.
func (l *pollEntryList) Front() *pollEntry {
	return l.head
}

// Back returns the last element of list l or nil.
func (l *pollEntryList) Back() *pollEntry {
	return l.tail
}

// PushFront inserts the element e at the front of list l.
func (l *pollEntryList) PushFront(e *pollEntry) {
	pollEntryElementMapper{}.linkerFor(e).SetNext(l.head)
	pollEntryElementMapper{}.linkerFor(e).SetPrev(nil)

	if l.head != nil {
		pollEntryElementMapper{}.linkerFor(l.head).SetPrev(e)
	} else {
		l.tail = e
	}

	l.head = e
}

// PushBack inserts the element e at the back of list l.
func (l *pollEntryList) PushBack(e *pollEntry) {
	pollEntryElementMapper{}.linkerFor(e).SetNext(nil)
	pollEntryElementMapper{}.linkerFor(e).SetPrev(l.tail)

	if l.tail != nil {
		pollEntryElementMapper{}.linkerFor(l.tail).SetNext(e)
	} else {
		l.head = e
	}

	l.tail = e
}

// PushBackList inserts list m at the end of list l, emptying m.
func (l *pollEntryList) PushBackList(m *pollEntryList) {
	if l.head == nil {
		l.head = m.head
		l.tail = m.tail
	} else if m.head != nil {
		pollEntryElementMapper{}.linkerFor(l.tail).SetNext(m.head)
		pollEntryElementMapper{}.linkerFor(m.head).SetPrev(l.tail)

		l.tail = m.tail
	}

	m.head = nil
	m.tail = nil
}

// InsertAfter inserts e after b.
func (l *pollEntryList) InsertAfter(b, e *pollEntry) {
	a := pollEntryElementMapper{}.linkerFor(b).Next()
	pollEntryElementMapper{}.linkerFor(e).SetNext(a)
	pollEntryElementMapper{}.linkerFor(e).SetPrev(b)
	pollEntryElementMapper{}.linkerFor(b).SetNext(e)

	if a != nil {
		pollEntryElementMapper{}.linkerFor(a).SetPrev(e)
	} else {
		l.tail = e
	}
}

// InsertBefore inserts e before a.
func (l *pollEntryList) InsertBefore(a, e *pollEntry) {
	b := pollEntryElementMapper{}.linkerFor(a).Prev()
	pollEntryElementMapper{}.linkerFor(e).SetNext(a)
	pollEntryElementMapper{}.linkerFor(e).SetPrev(b)
	pollEntryElementMapper{}.linkerFor(a).SetPrev(e)

	if b != nil {
		pollEntryElementMapper{}.linkerFor(b).SetNext(e)
	} else {
		l.head = e
	}
}

// Remove removes e from l.
func (l *pollEntryList) Remove(e *pollEntry) {
	prev := pollEntryElementMapper{}.linkerFor(e).Prev()
	next := pollEntryElementMapper{}.linkerFor(e).Next()

	if prev != nil {
		pollEntryElementMapper{}.linkerFor(prev).SetNext(next)
	} else {
		l.head = next
	}

	if next != nil {
		pollEntryElementMapper{}.linkerFor(next).SetPrev(prev)
	} else {
		l.tail = prev
	}
}

// Entry is a default implementation of Linker. Users can add anonymous fields
// of this type to their structs to make them automatically implement the
// methods needed by List.
//
// +stateify savable
type pollEntryEntry struct {
	next *pollEntry
	prev *pollEntry
}

// Next returns the entry that follows e in the list.
func (e *pollEntryEntry) Next() *pollEntry {
	return e.next
}

// Prev returns the entry that precedes e in the list.
func (e *pollEntryEntry) Prev() *pollEntry {
	return e.prev
}

// SetNext assigns 'entry' as the entry that follows e in the list.
func (e *pollEntryEntry) SetNext(elem *pollEntry) {
	e.next = elem
}

// SetPrev assigns 'entry' as the entry that precedes e in the list.
func (e *pollEntryEntry) SetPrev(elem *pollEntry) {
	e.prev = elem
}
