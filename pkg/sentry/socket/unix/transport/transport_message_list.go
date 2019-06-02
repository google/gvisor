package transport

// ElementMapper provides an identity mapping by default.
//
// This can be replaced to provide a struct that maps elements to linker
// objects, if they are not the same. An ElementMapper is not typically
// required if: Linker is left as is, Element is left as is, or Linker and
// Element are the same type.
type messageElementMapper struct{}

// linkerFor maps an Element to a Linker.
//
// This default implementation should be inlined.
//
//go:nosplit
func (messageElementMapper) linkerFor(elem *message) *message { return elem }

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
type messageList struct {
	head *message
	tail *message
}

// Reset resets list l to the empty state.
func (l *messageList) Reset() {
	l.head = nil
	l.tail = nil
}

// Empty returns true iff the list is empty.
func (l *messageList) Empty() bool {
	return l.head == nil
}

// Front returns the first element of list l or nil.
func (l *messageList) Front() *message {
	return l.head
}

// Back returns the last element of list l or nil.
func (l *messageList) Back() *message {
	return l.tail
}

// PushFront inserts the element e at the front of list l.
func (l *messageList) PushFront(e *message) {
	messageElementMapper{}.linkerFor(e).SetNext(l.head)
	messageElementMapper{}.linkerFor(e).SetPrev(nil)

	if l.head != nil {
		messageElementMapper{}.linkerFor(l.head).SetPrev(e)
	} else {
		l.tail = e
	}

	l.head = e
}

// PushBack inserts the element e at the back of list l.
func (l *messageList) PushBack(e *message) {
	messageElementMapper{}.linkerFor(e).SetNext(nil)
	messageElementMapper{}.linkerFor(e).SetPrev(l.tail)

	if l.tail != nil {
		messageElementMapper{}.linkerFor(l.tail).SetNext(e)
	} else {
		l.head = e
	}

	l.tail = e
}

// PushBackList inserts list m at the end of list l, emptying m.
func (l *messageList) PushBackList(m *messageList) {
	if l.head == nil {
		l.head = m.head
		l.tail = m.tail
	} else if m.head != nil {
		messageElementMapper{}.linkerFor(l.tail).SetNext(m.head)
		messageElementMapper{}.linkerFor(m.head).SetPrev(l.tail)

		l.tail = m.tail
	}

	m.head = nil
	m.tail = nil
}

// InsertAfter inserts e after b.
func (l *messageList) InsertAfter(b, e *message) {
	a := messageElementMapper{}.linkerFor(b).Next()
	messageElementMapper{}.linkerFor(e).SetNext(a)
	messageElementMapper{}.linkerFor(e).SetPrev(b)
	messageElementMapper{}.linkerFor(b).SetNext(e)

	if a != nil {
		messageElementMapper{}.linkerFor(a).SetPrev(e)
	} else {
		l.tail = e
	}
}

// InsertBefore inserts e before a.
func (l *messageList) InsertBefore(a, e *message) {
	b := messageElementMapper{}.linkerFor(a).Prev()
	messageElementMapper{}.linkerFor(e).SetNext(a)
	messageElementMapper{}.linkerFor(e).SetPrev(b)
	messageElementMapper{}.linkerFor(a).SetPrev(e)

	if b != nil {
		messageElementMapper{}.linkerFor(b).SetNext(e)
	} else {
		l.head = e
	}
}

// Remove removes e from l.
func (l *messageList) Remove(e *message) {
	prev := messageElementMapper{}.linkerFor(e).Prev()
	next := messageElementMapper{}.linkerFor(e).Next()

	if prev != nil {
		messageElementMapper{}.linkerFor(prev).SetNext(next)
	} else {
		l.head = next
	}

	if next != nil {
		messageElementMapper{}.linkerFor(next).SetPrev(prev)
	} else {
		l.tail = prev
	}
}

// Entry is a default implementation of Linker. Users can add anonymous fields
// of this type to their structs to make them automatically implement the
// methods needed by List.
//
// +stateify savable
type messageEntry struct {
	next *message
	prev *message
}

// Next returns the entry that follows e in the list.
func (e *messageEntry) Next() *message {
	return e.next
}

// Prev returns the entry that precedes e in the list.
func (e *messageEntry) Prev() *message {
	return e.prev
}

// SetNext assigns 'entry' as the entry that follows e in the list.
func (e *messageEntry) SetNext(elem *message) {
	e.next = elem
}

// SetPrev assigns 'entry' as the entry that precedes e in the list.
func (e *messageEntry) SetPrev(elem *message) {
	e.prev = elem
}
