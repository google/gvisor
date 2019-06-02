package fs

// ElementMapper provides an identity mapping by default.
//
// This can be replaced to provide a struct that maps elements to linker
// objects, if they are not the same. An ElementMapper is not typically
// required if: Linker is left as is, Element is left as is, or Linker and
// Element are the same type.
type eventElementMapper struct{}

// linkerFor maps an Element to a Linker.
//
// This default implementation should be inlined.
//
//go:nosplit
func (eventElementMapper) linkerFor(elem *Event) *Event { return elem }

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
type eventList struct {
	head *Event
	tail *Event
}

// Reset resets list l to the empty state.
func (l *eventList) Reset() {
	l.head = nil
	l.tail = nil
}

// Empty returns true iff the list is empty.
func (l *eventList) Empty() bool {
	return l.head == nil
}

// Front returns the first element of list l or nil.
func (l *eventList) Front() *Event {
	return l.head
}

// Back returns the last element of list l or nil.
func (l *eventList) Back() *Event {
	return l.tail
}

// PushFront inserts the element e at the front of list l.
func (l *eventList) PushFront(e *Event) {
	eventElementMapper{}.linkerFor(e).SetNext(l.head)
	eventElementMapper{}.linkerFor(e).SetPrev(nil)

	if l.head != nil {
		eventElementMapper{}.linkerFor(l.head).SetPrev(e)
	} else {
		l.tail = e
	}

	l.head = e
}

// PushBack inserts the element e at the back of list l.
func (l *eventList) PushBack(e *Event) {
	eventElementMapper{}.linkerFor(e).SetNext(nil)
	eventElementMapper{}.linkerFor(e).SetPrev(l.tail)

	if l.tail != nil {
		eventElementMapper{}.linkerFor(l.tail).SetNext(e)
	} else {
		l.head = e
	}

	l.tail = e
}

// PushBackList inserts list m at the end of list l, emptying m.
func (l *eventList) PushBackList(m *eventList) {
	if l.head == nil {
		l.head = m.head
		l.tail = m.tail
	} else if m.head != nil {
		eventElementMapper{}.linkerFor(l.tail).SetNext(m.head)
		eventElementMapper{}.linkerFor(m.head).SetPrev(l.tail)

		l.tail = m.tail
	}

	m.head = nil
	m.tail = nil
}

// InsertAfter inserts e after b.
func (l *eventList) InsertAfter(b, e *Event) {
	a := eventElementMapper{}.linkerFor(b).Next()
	eventElementMapper{}.linkerFor(e).SetNext(a)
	eventElementMapper{}.linkerFor(e).SetPrev(b)
	eventElementMapper{}.linkerFor(b).SetNext(e)

	if a != nil {
		eventElementMapper{}.linkerFor(a).SetPrev(e)
	} else {
		l.tail = e
	}
}

// InsertBefore inserts e before a.
func (l *eventList) InsertBefore(a, e *Event) {
	b := eventElementMapper{}.linkerFor(a).Prev()
	eventElementMapper{}.linkerFor(e).SetNext(a)
	eventElementMapper{}.linkerFor(e).SetPrev(b)
	eventElementMapper{}.linkerFor(a).SetPrev(e)

	if b != nil {
		eventElementMapper{}.linkerFor(b).SetNext(e)
	} else {
		l.head = e
	}
}

// Remove removes e from l.
func (l *eventList) Remove(e *Event) {
	prev := eventElementMapper{}.linkerFor(e).Prev()
	next := eventElementMapper{}.linkerFor(e).Next()

	if prev != nil {
		eventElementMapper{}.linkerFor(prev).SetNext(next)
	} else {
		l.head = next
	}

	if next != nil {
		eventElementMapper{}.linkerFor(next).SetPrev(prev)
	} else {
		l.tail = prev
	}
}

// Entry is a default implementation of Linker. Users can add anonymous fields
// of this type to their structs to make them automatically implement the
// methods needed by List.
//
// +stateify savable
type eventEntry struct {
	next *Event
	prev *Event
}

// Next returns the entry that follows e in the list.
func (e *eventEntry) Next() *Event {
	return e.next
}

// Prev returns the entry that precedes e in the list.
func (e *eventEntry) Prev() *Event {
	return e.prev
}

// SetNext assigns 'entry' as the entry that follows e in the list.
func (e *eventEntry) SetNext(elem *Event) {
	e.next = elem
}

// SetPrev assigns 'entry' as the entry that precedes e in the list.
func (e *eventEntry) SetPrev(elem *Event) {
	e.prev = elem
}
