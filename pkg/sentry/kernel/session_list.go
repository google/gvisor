package kernel

// ElementMapper provides an identity mapping by default.
//
// This can be replaced to provide a struct that maps elements to linker
// objects, if they are not the same. An ElementMapper is not typically
// required if: Linker is left as is, Element is left as is, or Linker and
// Element are the same type.
type sessionElementMapper struct{}

// linkerFor maps an Element to a Linker.
//
// This default implementation should be inlined.
//
//go:nosplit
func (sessionElementMapper) linkerFor(elem *Session) *Session { return elem }

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
type sessionList struct {
	head *Session
	tail *Session
}

// Reset resets list l to the empty state.
func (l *sessionList) Reset() {
	l.head = nil
	l.tail = nil
}

// Empty returns true iff the list is empty.
func (l *sessionList) Empty() bool {
	return l.head == nil
}

// Front returns the first element of list l or nil.
func (l *sessionList) Front() *Session {
	return l.head
}

// Back returns the last element of list l or nil.
func (l *sessionList) Back() *Session {
	return l.tail
}

// PushFront inserts the element e at the front of list l.
func (l *sessionList) PushFront(e *Session) {
	sessionElementMapper{}.linkerFor(e).SetNext(l.head)
	sessionElementMapper{}.linkerFor(e).SetPrev(nil)

	if l.head != nil {
		sessionElementMapper{}.linkerFor(l.head).SetPrev(e)
	} else {
		l.tail = e
	}

	l.head = e
}

// PushBack inserts the element e at the back of list l.
func (l *sessionList) PushBack(e *Session) {
	sessionElementMapper{}.linkerFor(e).SetNext(nil)
	sessionElementMapper{}.linkerFor(e).SetPrev(l.tail)

	if l.tail != nil {
		sessionElementMapper{}.linkerFor(l.tail).SetNext(e)
	} else {
		l.head = e
	}

	l.tail = e
}

// PushBackList inserts list m at the end of list l, emptying m.
func (l *sessionList) PushBackList(m *sessionList) {
	if l.head == nil {
		l.head = m.head
		l.tail = m.tail
	} else if m.head != nil {
		sessionElementMapper{}.linkerFor(l.tail).SetNext(m.head)
		sessionElementMapper{}.linkerFor(m.head).SetPrev(l.tail)

		l.tail = m.tail
	}

	m.head = nil
	m.tail = nil
}

// InsertAfter inserts e after b.
func (l *sessionList) InsertAfter(b, e *Session) {
	a := sessionElementMapper{}.linkerFor(b).Next()
	sessionElementMapper{}.linkerFor(e).SetNext(a)
	sessionElementMapper{}.linkerFor(e).SetPrev(b)
	sessionElementMapper{}.linkerFor(b).SetNext(e)

	if a != nil {
		sessionElementMapper{}.linkerFor(a).SetPrev(e)
	} else {
		l.tail = e
	}
}

// InsertBefore inserts e before a.
func (l *sessionList) InsertBefore(a, e *Session) {
	b := sessionElementMapper{}.linkerFor(a).Prev()
	sessionElementMapper{}.linkerFor(e).SetNext(a)
	sessionElementMapper{}.linkerFor(e).SetPrev(b)
	sessionElementMapper{}.linkerFor(a).SetPrev(e)

	if b != nil {
		sessionElementMapper{}.linkerFor(b).SetNext(e)
	} else {
		l.head = e
	}
}

// Remove removes e from l.
func (l *sessionList) Remove(e *Session) {
	prev := sessionElementMapper{}.linkerFor(e).Prev()
	next := sessionElementMapper{}.linkerFor(e).Next()

	if prev != nil {
		sessionElementMapper{}.linkerFor(prev).SetNext(next)
	} else {
		l.head = next
	}

	if next != nil {
		sessionElementMapper{}.linkerFor(next).SetPrev(prev)
	} else {
		l.tail = prev
	}
}

// Entry is a default implementation of Linker. Users can add anonymous fields
// of this type to their structs to make them automatically implement the
// methods needed by List.
//
// +stateify savable
type sessionEntry struct {
	next *Session
	prev *Session
}

// Next returns the entry that follows e in the list.
func (e *sessionEntry) Next() *Session {
	return e.next
}

// Prev returns the entry that precedes e in the list.
func (e *sessionEntry) Prev() *Session {
	return e.prev
}

// SetNext assigns 'entry' as the entry that follows e in the list.
func (e *sessionEntry) SetNext(elem *Session) {
	e.next = elem
}

// SetPrev assigns 'entry' as the entry that precedes e in the list.
func (e *sessionEntry) SetPrev(elem *Session) {
	e.prev = elem
}
