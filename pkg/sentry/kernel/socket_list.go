package kernel

// ElementMapper provides an identity mapping by default.
//
// This can be replaced to provide a struct that maps elements to linker
// objects, if they are not the same. An ElementMapper is not typically
// required if: Linker is left as is, Element is left as is, or Linker and
// Element are the same type.
type socketElementMapper struct{}

// linkerFor maps an Element to a Linker.
//
// This default implementation should be inlined.
//
//go:nosplit
func (socketElementMapper) linkerFor(elem *SocketEntry) *SocketEntry { return elem }

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
type socketList struct {
	head *SocketEntry
	tail *SocketEntry
}

// Reset resets list l to the empty state.
func (l *socketList) Reset() {
	l.head = nil
	l.tail = nil
}

// Empty returns true iff the list is empty.
func (l *socketList) Empty() bool {
	return l.head == nil
}

// Front returns the first element of list l or nil.
func (l *socketList) Front() *SocketEntry {
	return l.head
}

// Back returns the last element of list l or nil.
func (l *socketList) Back() *SocketEntry {
	return l.tail
}

// PushFront inserts the element e at the front of list l.
func (l *socketList) PushFront(e *SocketEntry) {
	socketElementMapper{}.linkerFor(e).SetNext(l.head)
	socketElementMapper{}.linkerFor(e).SetPrev(nil)

	if l.head != nil {
		socketElementMapper{}.linkerFor(l.head).SetPrev(e)
	} else {
		l.tail = e
	}

	l.head = e
}

// PushBack inserts the element e at the back of list l.
func (l *socketList) PushBack(e *SocketEntry) {
	socketElementMapper{}.linkerFor(e).SetNext(nil)
	socketElementMapper{}.linkerFor(e).SetPrev(l.tail)

	if l.tail != nil {
		socketElementMapper{}.linkerFor(l.tail).SetNext(e)
	} else {
		l.head = e
	}

	l.tail = e
}

// PushBackList inserts list m at the end of list l, emptying m.
func (l *socketList) PushBackList(m *socketList) {
	if l.head == nil {
		l.head = m.head
		l.tail = m.tail
	} else if m.head != nil {
		socketElementMapper{}.linkerFor(l.tail).SetNext(m.head)
		socketElementMapper{}.linkerFor(m.head).SetPrev(l.tail)

		l.tail = m.tail
	}

	m.head = nil
	m.tail = nil
}

// InsertAfter inserts e after b.
func (l *socketList) InsertAfter(b, e *SocketEntry) {
	a := socketElementMapper{}.linkerFor(b).Next()
	socketElementMapper{}.linkerFor(e).SetNext(a)
	socketElementMapper{}.linkerFor(e).SetPrev(b)
	socketElementMapper{}.linkerFor(b).SetNext(e)

	if a != nil {
		socketElementMapper{}.linkerFor(a).SetPrev(e)
	} else {
		l.tail = e
	}
}

// InsertBefore inserts e before a.
func (l *socketList) InsertBefore(a, e *SocketEntry) {
	b := socketElementMapper{}.linkerFor(a).Prev()
	socketElementMapper{}.linkerFor(e).SetNext(a)
	socketElementMapper{}.linkerFor(e).SetPrev(b)
	socketElementMapper{}.linkerFor(a).SetPrev(e)

	if b != nil {
		socketElementMapper{}.linkerFor(b).SetNext(e)
	} else {
		l.head = e
	}
}

// Remove removes e from l.
func (l *socketList) Remove(e *SocketEntry) {
	prev := socketElementMapper{}.linkerFor(e).Prev()
	next := socketElementMapper{}.linkerFor(e).Next()

	if prev != nil {
		socketElementMapper{}.linkerFor(prev).SetNext(next)
	} else {
		l.head = next
	}

	if next != nil {
		socketElementMapper{}.linkerFor(next).SetPrev(prev)
	} else {
		l.tail = prev
	}
}

// Entry is a default implementation of Linker. Users can add anonymous fields
// of this type to their structs to make them automatically implement the
// methods needed by List.
//
// +stateify savable
type socketEntry struct {
	next *SocketEntry
	prev *SocketEntry
}

// Next returns the entry that follows e in the list.
func (e *socketEntry) Next() *SocketEntry {
	return e.next
}

// Prev returns the entry that precedes e in the list.
func (e *socketEntry) Prev() *SocketEntry {
	return e.prev
}

// SetNext assigns 'entry' as the entry that follows e in the list.
func (e *socketEntry) SetNext(elem *SocketEntry) {
	e.next = elem
}

// SetPrev assigns 'entry' as the entry that precedes e in the list.
func (e *socketEntry) SetPrev(elem *SocketEntry) {
	e.prev = elem
}
