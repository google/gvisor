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
//
//go:nosplit
func (l *linkAddrEntryList) Empty() bool {
	return l.head == nil
}

// Front returns the first element of list l or nil.
//
//go:nosplit
func (l *linkAddrEntryList) Front() *linkAddrEntry {
	return l.head
}

// Back returns the last element of list l or nil.
//
//go:nosplit
func (l *linkAddrEntryList) Back() *linkAddrEntry {
	return l.tail
}

// Len returns the number of elements in the list.
//
// NOTE: This is an O(n) operation.
//
//go:nosplit
func (l *linkAddrEntryList) Len() (count int) {
	for e := l.Front(); e != nil; e = (linkAddrEntryElementMapper{}.linkerFor(e)).Next() {
		count++
	}
	return count
}

// PushFront inserts the element e at the front of list l.
//
//go:nosplit
func (l *linkAddrEntryList) PushFront(e *linkAddrEntry) {
	linker := linkAddrEntryElementMapper{}.linkerFor(e)
	linker.SetNext(l.head)
	linker.SetPrev(nil)
	if l.head != nil {
		linkAddrEntryElementMapper{}.linkerFor(l.head).SetPrev(e)
	} else {
		l.tail = e
	}

	l.head = e
}

// PushBack inserts the element e at the back of list l.
//
//go:nosplit
func (l *linkAddrEntryList) PushBack(e *linkAddrEntry) {
	linker := linkAddrEntryElementMapper{}.linkerFor(e)
	linker.SetNext(nil)
	linker.SetPrev(l.tail)
	if l.tail != nil {
		linkAddrEntryElementMapper{}.linkerFor(l.tail).SetNext(e)
	} else {
		l.head = e
	}

	l.tail = e
}

// PushBackList inserts list m at the end of list l, emptying m.
//
//go:nosplit
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
//
//go:nosplit
func (l *linkAddrEntryList) InsertAfter(b, e *linkAddrEntry) {
	bLinker := linkAddrEntryElementMapper{}.linkerFor(b)
	eLinker := linkAddrEntryElementMapper{}.linkerFor(e)

	a := bLinker.Next()

	eLinker.SetNext(a)
	eLinker.SetPrev(b)
	bLinker.SetNext(e)

	if a != nil {
		linkAddrEntryElementMapper{}.linkerFor(a).SetPrev(e)
	} else {
		l.tail = e
	}
}

// InsertBefore inserts e before a.
//
//go:nosplit
func (l *linkAddrEntryList) InsertBefore(a, e *linkAddrEntry) {
	aLinker := linkAddrEntryElementMapper{}.linkerFor(a)
	eLinker := linkAddrEntryElementMapper{}.linkerFor(e)

	b := aLinker.Prev()
	eLinker.SetNext(a)
	eLinker.SetPrev(b)
	aLinker.SetPrev(e)

	if b != nil {
		linkAddrEntryElementMapper{}.linkerFor(b).SetNext(e)
	} else {
		l.head = e
	}
}

// Remove removes e from l.
//
//go:nosplit
func (l *linkAddrEntryList) Remove(e *linkAddrEntry) {
	linker := linkAddrEntryElementMapper{}.linkerFor(e)
	prev := linker.Prev()
	next := linker.Next()

	if prev != nil {
		linkAddrEntryElementMapper{}.linkerFor(prev).SetNext(next)
	} else if l.head == e {
		l.head = next
	}

	if next != nil {
		linkAddrEntryElementMapper{}.linkerFor(next).SetPrev(prev)
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
type linkAddrEntryEntry struct {
	next *linkAddrEntry
	prev *linkAddrEntry
}

// Next returns the entry that follows e in the list.
//
//go:nosplit
func (e *linkAddrEntryEntry) Next() *linkAddrEntry {
	return e.next
}

// Prev returns the entry that precedes e in the list.
//
//go:nosplit
func (e *linkAddrEntryEntry) Prev() *linkAddrEntry {
	return e.prev
}

// SetNext assigns 'entry' as the entry that follows e in the list.
//
//go:nosplit
func (e *linkAddrEntryEntry) SetNext(elem *linkAddrEntry) {
	e.next = elem
}

// SetPrev assigns 'entry' as the entry that precedes e in the list.
//
//go:nosplit
func (e *linkAddrEntryEntry) SetPrev(elem *linkAddrEntry) {
	e.prev = elem
}
