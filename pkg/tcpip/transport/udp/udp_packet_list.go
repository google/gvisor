package udp

// ElementMapper provides an identity mapping by default.
//
// This can be replaced to provide a struct that maps elements to linker
// objects, if they are not the same. An ElementMapper is not typically
// required if: Linker is left as is, Element is left as is, or Linker and
// Element are the same type.
type udpPacketElementMapper struct{}

// linkerFor maps an Element to a Linker.
//
// This default implementation should be inlined.
//
//go:nosplit
func (udpPacketElementMapper) linkerFor(elem *udpPacket) *udpPacket { return elem }

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
type udpPacketList struct {
	head *udpPacket
	tail *udpPacket
}

// Reset resets list l to the empty state.
func (l *udpPacketList) Reset() {
	l.head = nil
	l.tail = nil
}

// Empty returns true iff the list is empty.
func (l *udpPacketList) Empty() bool {
	return l.head == nil
}

// Front returns the first element of list l or nil.
func (l *udpPacketList) Front() *udpPacket {
	return l.head
}

// Back returns the last element of list l or nil.
func (l *udpPacketList) Back() *udpPacket {
	return l.tail
}

// PushFront inserts the element e at the front of list l.
func (l *udpPacketList) PushFront(e *udpPacket) {
	udpPacketElementMapper{}.linkerFor(e).SetNext(l.head)
	udpPacketElementMapper{}.linkerFor(e).SetPrev(nil)

	if l.head != nil {
		udpPacketElementMapper{}.linkerFor(l.head).SetPrev(e)
	} else {
		l.tail = e
	}

	l.head = e
}

// PushBack inserts the element e at the back of list l.
func (l *udpPacketList) PushBack(e *udpPacket) {
	udpPacketElementMapper{}.linkerFor(e).SetNext(nil)
	udpPacketElementMapper{}.linkerFor(e).SetPrev(l.tail)

	if l.tail != nil {
		udpPacketElementMapper{}.linkerFor(l.tail).SetNext(e)
	} else {
		l.head = e
	}

	l.tail = e
}

// PushBackList inserts list m at the end of list l, emptying m.
func (l *udpPacketList) PushBackList(m *udpPacketList) {
	if l.head == nil {
		l.head = m.head
		l.tail = m.tail
	} else if m.head != nil {
		udpPacketElementMapper{}.linkerFor(l.tail).SetNext(m.head)
		udpPacketElementMapper{}.linkerFor(m.head).SetPrev(l.tail)

		l.tail = m.tail
	}

	m.head = nil
	m.tail = nil
}

// InsertAfter inserts e after b.
func (l *udpPacketList) InsertAfter(b, e *udpPacket) {
	a := udpPacketElementMapper{}.linkerFor(b).Next()
	udpPacketElementMapper{}.linkerFor(e).SetNext(a)
	udpPacketElementMapper{}.linkerFor(e).SetPrev(b)
	udpPacketElementMapper{}.linkerFor(b).SetNext(e)

	if a != nil {
		udpPacketElementMapper{}.linkerFor(a).SetPrev(e)
	} else {
		l.tail = e
	}
}

// InsertBefore inserts e before a.
func (l *udpPacketList) InsertBefore(a, e *udpPacket) {
	b := udpPacketElementMapper{}.linkerFor(a).Prev()
	udpPacketElementMapper{}.linkerFor(e).SetNext(a)
	udpPacketElementMapper{}.linkerFor(e).SetPrev(b)
	udpPacketElementMapper{}.linkerFor(a).SetPrev(e)

	if b != nil {
		udpPacketElementMapper{}.linkerFor(b).SetNext(e)
	} else {
		l.head = e
	}
}

// Remove removes e from l.
func (l *udpPacketList) Remove(e *udpPacket) {
	prev := udpPacketElementMapper{}.linkerFor(e).Prev()
	next := udpPacketElementMapper{}.linkerFor(e).Next()

	if prev != nil {
		udpPacketElementMapper{}.linkerFor(prev).SetNext(next)
	} else {
		l.head = next
	}

	if next != nil {
		udpPacketElementMapper{}.linkerFor(next).SetPrev(prev)
	} else {
		l.tail = prev
	}
}

// Entry is a default implementation of Linker. Users can add anonymous fields
// of this type to their structs to make them automatically implement the
// methods needed by List.
//
// +stateify savable
type udpPacketEntry struct {
	next *udpPacket
	prev *udpPacket
}

// Next returns the entry that follows e in the list.
func (e *udpPacketEntry) Next() *udpPacket {
	return e.next
}

// Prev returns the entry that precedes e in the list.
func (e *udpPacketEntry) Prev() *udpPacket {
	return e.prev
}

// SetNext assigns 'entry' as the entry that follows e in the list.
func (e *udpPacketEntry) SetNext(elem *udpPacket) {
	e.next = elem
}

// SetPrev assigns 'entry' as the entry that precedes e in the list.
func (e *udpPacketEntry) SetPrev(elem *udpPacket) {
	e.prev = elem
}
