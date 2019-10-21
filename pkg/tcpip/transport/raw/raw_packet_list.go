package raw

// ElementMapper provides an identity mapping by default.
//
// This can be replaced to provide a struct that maps elements to linker
// objects, if they are not the same. An ElementMapper is not typically
// required if: Linker is left as is, Element is left as is, or Linker and
// Element are the same type.
type rawPacketElementMapper struct{}

// linkerFor maps an Element to a Linker.
//
// This default implementation should be inlined.
//
//go:nosplit
func (rawPacketElementMapper) linkerFor(elem *rawPacket) *rawPacket { return elem }

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
type rawPacketList struct {
	head *rawPacket
	tail *rawPacket
}

// Reset resets list l to the empty state.
func (l *rawPacketList) Reset() {
	l.head = nil
	l.tail = nil
}

// Empty returns true iff the list is empty.
func (l *rawPacketList) Empty() bool {
	return l.head == nil
}

// Front returns the first element of list l or nil.
func (l *rawPacketList) Front() *rawPacket {
	return l.head
}

// Back returns the last element of list l or nil.
func (l *rawPacketList) Back() *rawPacket {
	return l.tail
}

// PushFront inserts the element e at the front of list l.
func (l *rawPacketList) PushFront(e *rawPacket) {
	rawPacketElementMapper{}.linkerFor(e).SetNext(l.head)
	rawPacketElementMapper{}.linkerFor(e).SetPrev(nil)

	if l.head != nil {
		rawPacketElementMapper{}.linkerFor(l.head).SetPrev(e)
	} else {
		l.tail = e
	}

	l.head = e
}

// PushBack inserts the element e at the back of list l.
func (l *rawPacketList) PushBack(e *rawPacket) {
	rawPacketElementMapper{}.linkerFor(e).SetNext(nil)
	rawPacketElementMapper{}.linkerFor(e).SetPrev(l.tail)

	if l.tail != nil {
		rawPacketElementMapper{}.linkerFor(l.tail).SetNext(e)
	} else {
		l.head = e
	}

	l.tail = e
}

// PushBackList inserts list m at the end of list l, emptying m.
func (l *rawPacketList) PushBackList(m *rawPacketList) {
	if l.head == nil {
		l.head = m.head
		l.tail = m.tail
	} else if m.head != nil {
		rawPacketElementMapper{}.linkerFor(l.tail).SetNext(m.head)
		rawPacketElementMapper{}.linkerFor(m.head).SetPrev(l.tail)

		l.tail = m.tail
	}

	m.head = nil
	m.tail = nil
}

// InsertAfter inserts e after b.
func (l *rawPacketList) InsertAfter(b, e *rawPacket) {
	a := rawPacketElementMapper{}.linkerFor(b).Next()
	rawPacketElementMapper{}.linkerFor(e).SetNext(a)
	rawPacketElementMapper{}.linkerFor(e).SetPrev(b)
	rawPacketElementMapper{}.linkerFor(b).SetNext(e)

	if a != nil {
		rawPacketElementMapper{}.linkerFor(a).SetPrev(e)
	} else {
		l.tail = e
	}
}

// InsertBefore inserts e before a.
func (l *rawPacketList) InsertBefore(a, e *rawPacket) {
	b := rawPacketElementMapper{}.linkerFor(a).Prev()
	rawPacketElementMapper{}.linkerFor(e).SetNext(a)
	rawPacketElementMapper{}.linkerFor(e).SetPrev(b)
	rawPacketElementMapper{}.linkerFor(a).SetPrev(e)

	if b != nil {
		rawPacketElementMapper{}.linkerFor(b).SetNext(e)
	} else {
		l.head = e
	}
}

// Remove removes e from l.
func (l *rawPacketList) Remove(e *rawPacket) {
	prev := rawPacketElementMapper{}.linkerFor(e).Prev()
	next := rawPacketElementMapper{}.linkerFor(e).Next()

	if prev != nil {
		rawPacketElementMapper{}.linkerFor(prev).SetNext(next)
	} else {
		l.head = next
	}

	if next != nil {
		rawPacketElementMapper{}.linkerFor(next).SetPrev(prev)
	} else {
		l.tail = prev
	}
}

// Entry is a default implementation of Linker. Users can add anonymous fields
// of this type to their structs to make them automatically implement the
// methods needed by List.
//
// +stateify savable
type rawPacketEntry struct {
	next *rawPacket
	prev *rawPacket
}

// Next returns the entry that follows e in the list.
func (e *rawPacketEntry) Next() *rawPacket {
	return e.next
}

// Prev returns the entry that precedes e in the list.
func (e *rawPacketEntry) Prev() *rawPacket {
	return e.prev
}

// SetNext assigns 'entry' as the entry that follows e in the list.
func (e *rawPacketEntry) SetNext(elem *rawPacket) {
	e.next = elem
}

// SetPrev assigns 'entry' as the entry that precedes e in the list.
func (e *rawPacketEntry) SetPrev(elem *rawPacket) {
	e.prev = elem
}
