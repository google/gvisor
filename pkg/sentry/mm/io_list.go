package mm

// ElementMapper provides an identity mapping by default.
//
// This can be replaced to provide a struct that maps elements to linker
// objects, if they are not the same. An ElementMapper is not typically
// required if: Linker is left as is, Element is left as is, or Linker and
// Element are the same type.
type ioElementMapper struct{}

// linkerFor maps an Element to a Linker.
//
// This default implementation should be inlined.
//
//go:nosplit
func (ioElementMapper) linkerFor(elem *ioResult) *ioResult { return elem }

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
type ioList struct {
	head *ioResult
	tail *ioResult
}

// Reset resets list l to the empty state.
func (l *ioList) Reset() {
	l.head = nil
	l.tail = nil
}

// Empty returns true iff the list is empty.
func (l *ioList) Empty() bool {
	return l.head == nil
}

// Front returns the first element of list l or nil.
func (l *ioList) Front() *ioResult {
	return l.head
}

// Back returns the last element of list l or nil.
func (l *ioList) Back() *ioResult {
	return l.tail
}

// PushFront inserts the element e at the front of list l.
func (l *ioList) PushFront(e *ioResult) {
	ioElementMapper{}.linkerFor(e).SetNext(l.head)
	ioElementMapper{}.linkerFor(e).SetPrev(nil)

	if l.head != nil {
		ioElementMapper{}.linkerFor(l.head).SetPrev(e)
	} else {
		l.tail = e
	}

	l.head = e
}

// PushBack inserts the element e at the back of list l.
func (l *ioList) PushBack(e *ioResult) {
	ioElementMapper{}.linkerFor(e).SetNext(nil)
	ioElementMapper{}.linkerFor(e).SetPrev(l.tail)

	if l.tail != nil {
		ioElementMapper{}.linkerFor(l.tail).SetNext(e)
	} else {
		l.head = e
	}

	l.tail = e
}

// PushBackList inserts list m at the end of list l, emptying m.
func (l *ioList) PushBackList(m *ioList) {
	if l.head == nil {
		l.head = m.head
		l.tail = m.tail
	} else if m.head != nil {
		ioElementMapper{}.linkerFor(l.tail).SetNext(m.head)
		ioElementMapper{}.linkerFor(m.head).SetPrev(l.tail)

		l.tail = m.tail
	}

	m.head = nil
	m.tail = nil
}

// InsertAfter inserts e after b.
func (l *ioList) InsertAfter(b, e *ioResult) {
	a := ioElementMapper{}.linkerFor(b).Next()
	ioElementMapper{}.linkerFor(e).SetNext(a)
	ioElementMapper{}.linkerFor(e).SetPrev(b)
	ioElementMapper{}.linkerFor(b).SetNext(e)

	if a != nil {
		ioElementMapper{}.linkerFor(a).SetPrev(e)
	} else {
		l.tail = e
	}
}

// InsertBefore inserts e before a.
func (l *ioList) InsertBefore(a, e *ioResult) {
	b := ioElementMapper{}.linkerFor(a).Prev()
	ioElementMapper{}.linkerFor(e).SetNext(a)
	ioElementMapper{}.linkerFor(e).SetPrev(b)
	ioElementMapper{}.linkerFor(a).SetPrev(e)

	if b != nil {
		ioElementMapper{}.linkerFor(b).SetNext(e)
	} else {
		l.head = e
	}
}

// Remove removes e from l.
func (l *ioList) Remove(e *ioResult) {
	prev := ioElementMapper{}.linkerFor(e).Prev()
	next := ioElementMapper{}.linkerFor(e).Next()

	if prev != nil {
		ioElementMapper{}.linkerFor(prev).SetNext(next)
	} else {
		l.head = next
	}

	if next != nil {
		ioElementMapper{}.linkerFor(next).SetPrev(prev)
	} else {
		l.tail = prev
	}
}

// Entry is a default implementation of Linker. Users can add anonymous fields
// of this type to their structs to make them automatically implement the
// methods needed by List.
//
// +stateify savable
type ioEntry struct {
	next *ioResult
	prev *ioResult
}

// Next returns the entry that follows e in the list.
func (e *ioEntry) Next() *ioResult {
	return e.next
}

// Prev returns the entry that precedes e in the list.
func (e *ioEntry) Prev() *ioResult {
	return e.prev
}

// SetNext assigns 'entry' as the entry that follows e in the list.
func (e *ioEntry) SetNext(elem *ioResult) {
	e.next = elem
}

// SetPrev assigns 'entry' as the entry that precedes e in the list.
func (e *ioEntry) SetPrev(elem *ioResult) {
	e.prev = elem
}
