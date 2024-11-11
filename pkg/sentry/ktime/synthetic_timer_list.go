package ktime

// ElementMapper provides an identity mapping by default.
//
// This can be replaced to provide a struct that maps elements to linker
// objects, if they are not the same. An ElementMapper is not typically
// required if: Linker is left as is, Element is left as is, or Linker and
// Element are the same type.
type syntheticTimerElementMapper struct{}

// linkerFor maps an Element to a Linker.
//
// This default implementation should be inlined.
//
//go:nosplit
func (syntheticTimerElementMapper) linkerFor(elem *SyntheticTimer) *SyntheticTimer { return elem }

// List is an intrusive list. Entries can be added to or removed from the list
// in O(1) time and with no additional memory allocations.
//
// The zero value for List is an empty list ready to use.
//
// To iterate over a list (where l is a List):
//
//	for e := l.Front(); e != nil; e = e.Next() {
//		// do something with e.
//	}
//
// +stateify savable
type syntheticTimerList struct {
	head *SyntheticTimer
	tail *SyntheticTimer
}

// Reset resets list l to the empty state.
func (l *syntheticTimerList) Reset() {
	l.head = nil
	l.tail = nil
}

// Empty returns true iff the list is empty.
//
//go:nosplit
func (l *syntheticTimerList) Empty() bool {
	return l.head == nil
}

// Front returns the first element of list l or nil.
//
//go:nosplit
func (l *syntheticTimerList) Front() *SyntheticTimer {
	return l.head
}

// Back returns the last element of list l or nil.
//
//go:nosplit
func (l *syntheticTimerList) Back() *SyntheticTimer {
	return l.tail
}

// Len returns the number of elements in the list.
//
// NOTE: This is an O(n) operation.
//
//go:nosplit
func (l *syntheticTimerList) Len() (count int) {
	for e := l.Front(); e != nil; e = (syntheticTimerElementMapper{}.linkerFor(e)).Next() {
		count++
	}
	return count
}

// PushFront inserts the element e at the front of list l.
//
//go:nosplit
func (l *syntheticTimerList) PushFront(e *SyntheticTimer) {
	linker := syntheticTimerElementMapper{}.linkerFor(e)
	linker.SetNext(l.head)
	linker.SetPrev(nil)
	if l.head != nil {
		syntheticTimerElementMapper{}.linkerFor(l.head).SetPrev(e)
	} else {
		l.tail = e
	}

	l.head = e
}

// PushFrontList inserts list m at the start of list l, emptying m.
//
//go:nosplit
func (l *syntheticTimerList) PushFrontList(m *syntheticTimerList) {
	if l.head == nil {
		l.head = m.head
		l.tail = m.tail
	} else if m.head != nil {
		syntheticTimerElementMapper{}.linkerFor(l.head).SetPrev(m.tail)
		syntheticTimerElementMapper{}.linkerFor(m.tail).SetNext(l.head)

		l.head = m.head
	}
	m.head = nil
	m.tail = nil
}

// PushBack inserts the element e at the back of list l.
//
//go:nosplit
func (l *syntheticTimerList) PushBack(e *SyntheticTimer) {
	linker := syntheticTimerElementMapper{}.linkerFor(e)
	linker.SetNext(nil)
	linker.SetPrev(l.tail)
	if l.tail != nil {
		syntheticTimerElementMapper{}.linkerFor(l.tail).SetNext(e)
	} else {
		l.head = e
	}

	l.tail = e
}

// PushBackList inserts list m at the end of list l, emptying m.
//
//go:nosplit
func (l *syntheticTimerList) PushBackList(m *syntheticTimerList) {
	if l.head == nil {
		l.head = m.head
		l.tail = m.tail
	} else if m.head != nil {
		syntheticTimerElementMapper{}.linkerFor(l.tail).SetNext(m.head)
		syntheticTimerElementMapper{}.linkerFor(m.head).SetPrev(l.tail)

		l.tail = m.tail
	}
	m.head = nil
	m.tail = nil
}

// InsertAfter inserts e after b.
//
//go:nosplit
func (l *syntheticTimerList) InsertAfter(b, e *SyntheticTimer) {
	bLinker := syntheticTimerElementMapper{}.linkerFor(b)
	eLinker := syntheticTimerElementMapper{}.linkerFor(e)

	a := bLinker.Next()

	eLinker.SetNext(a)
	eLinker.SetPrev(b)
	bLinker.SetNext(e)

	if a != nil {
		syntheticTimerElementMapper{}.linkerFor(a).SetPrev(e)
	} else {
		l.tail = e
	}
}

// InsertBefore inserts e before a.
//
//go:nosplit
func (l *syntheticTimerList) InsertBefore(a, e *SyntheticTimer) {
	aLinker := syntheticTimerElementMapper{}.linkerFor(a)
	eLinker := syntheticTimerElementMapper{}.linkerFor(e)

	b := aLinker.Prev()
	eLinker.SetNext(a)
	eLinker.SetPrev(b)
	aLinker.SetPrev(e)

	if b != nil {
		syntheticTimerElementMapper{}.linkerFor(b).SetNext(e)
	} else {
		l.head = e
	}
}

// Remove removes e from l.
//
//go:nosplit
func (l *syntheticTimerList) Remove(e *SyntheticTimer) {
	linker := syntheticTimerElementMapper{}.linkerFor(e)
	prev := linker.Prev()
	next := linker.Next()

	if prev != nil {
		syntheticTimerElementMapper{}.linkerFor(prev).SetNext(next)
	} else if l.head == e {
		l.head = next
	}

	if next != nil {
		syntheticTimerElementMapper{}.linkerFor(next).SetPrev(prev)
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
type syntheticTimerEntry struct {
	next *SyntheticTimer
	prev *SyntheticTimer
}

// Next returns the entry that follows e in the list.
//
//go:nosplit
func (e *syntheticTimerEntry) Next() *SyntheticTimer {
	return e.next
}

// Prev returns the entry that precedes e in the list.
//
//go:nosplit
func (e *syntheticTimerEntry) Prev() *SyntheticTimer {
	return e.prev
}

// SetNext assigns 'entry' as the entry that follows e in the list.
//
//go:nosplit
func (e *syntheticTimerEntry) SetNext(elem *SyntheticTimer) {
	e.next = elem
}

// SetPrev assigns 'entry' as the entry that precedes e in the list.
//
//go:nosplit
func (e *syntheticTimerEntry) SetPrev(elem *SyntheticTimer) {
	e.prev = elem
}
