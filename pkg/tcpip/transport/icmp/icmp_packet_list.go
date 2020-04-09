package icmp

// ElementMapper provides an identity mapping by default.
//
// This can be replaced to provide a struct that maps elements to linker
// objects, if they are not the same. An ElementMapper is not typically
// required if: Linker is left as is, Element is left as is, or Linker and
// Element are the same type.
type icmpPacketElementMapper struct{}

// linkerFor maps an Element to a Linker.
//
// This default implementation should be inlined.
//
//go:nosplit
func (icmpPacketElementMapper) linkerFor(elem *icmpPacket) *icmpPacket { return elem }

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
type icmpPacketList struct {
	head *icmpPacket
	tail *icmpPacket
}

// Reset resets list l to the empty state.
func (l *icmpPacketList) Reset() {
	l.head = nil
	l.tail = nil
}

// Empty returns true iff the list is empty.
func (l *icmpPacketList) Empty() bool {
	return l.head == nil
}

// Front returns the first element of list l or nil.
func (l *icmpPacketList) Front() *icmpPacket {
	return l.head
}

// Back returns the last element of list l or nil.
func (l *icmpPacketList) Back() *icmpPacket {
	return l.tail
}

// Len returns the number of elements in the list.
//
// NOTE: This is an O(n) operation.
func (l *icmpPacketList) Len() (count int) {
	for e := l.Front(); e != nil; e = e.Next() {
		count++
	}
	return count
}

// PushFront inserts the element e at the front of list l.
func (l *icmpPacketList) PushFront(e *icmpPacket) {
	linker := icmpPacketElementMapper{}.linkerFor(e)
	linker.SetNext(l.head)
	linker.SetPrev(nil)
	if l.head != nil {
		icmpPacketElementMapper{}.linkerFor(l.head).SetPrev(e)
	} else {
		l.tail = e
	}

	l.head = e
}

// PushBack inserts the element e at the back of list l.
func (l *icmpPacketList) PushBack(e *icmpPacket) {
	linker := icmpPacketElementMapper{}.linkerFor(e)
	linker.SetNext(nil)
	linker.SetPrev(l.tail)
	if l.tail != nil {
		icmpPacketElementMapper{}.linkerFor(l.tail).SetNext(e)
	} else {
		l.head = e
	}

	l.tail = e
}

// PushBackList inserts list m at the end of list l, emptying m.
func (l *icmpPacketList) PushBackList(m *icmpPacketList) {
	if l.head == nil {
		l.head = m.head
		l.tail = m.tail
	} else if m.head != nil {
		icmpPacketElementMapper{}.linkerFor(l.tail).SetNext(m.head)
		icmpPacketElementMapper{}.linkerFor(m.head).SetPrev(l.tail)

		l.tail = m.tail
	}
	m.head = nil
	m.tail = nil
}

// InsertAfter inserts e after b.
func (l *icmpPacketList) InsertAfter(b, e *icmpPacket) {
	bLinker := icmpPacketElementMapper{}.linkerFor(b)
	eLinker := icmpPacketElementMapper{}.linkerFor(e)

	a := bLinker.Next()

	eLinker.SetNext(a)
	eLinker.SetPrev(b)
	bLinker.SetNext(e)

	if a != nil {
		icmpPacketElementMapper{}.linkerFor(a).SetPrev(e)
	} else {
		l.tail = e
	}
}

// InsertBefore inserts e before a.
func (l *icmpPacketList) InsertBefore(a, e *icmpPacket) {
	aLinker := icmpPacketElementMapper{}.linkerFor(a)
	eLinker := icmpPacketElementMapper{}.linkerFor(e)

	b := aLinker.Prev()
	eLinker.SetNext(a)
	eLinker.SetPrev(b)
	aLinker.SetPrev(e)

	if b != nil {
		icmpPacketElementMapper{}.linkerFor(b).SetNext(e)
	} else {
		l.head = e
	}
}

// Remove removes e from l.
func (l *icmpPacketList) Remove(e *icmpPacket) {
	linker := icmpPacketElementMapper{}.linkerFor(e)
	prev := linker.Prev()
	next := linker.Next()

	if prev != nil {
		icmpPacketElementMapper{}.linkerFor(prev).SetNext(next)
	} else {
		l.head = next
	}

	if next != nil {
		icmpPacketElementMapper{}.linkerFor(next).SetPrev(prev)
	} else {
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
type icmpPacketEntry struct {
	next *icmpPacket
	prev *icmpPacket
}

// Next returns the entry that follows e in the list.
func (e *icmpPacketEntry) Next() *icmpPacket {
	return e.next
}

// Prev returns the entry that precedes e in the list.
func (e *icmpPacketEntry) Prev() *icmpPacket {
	return e.prev
}

// SetNext assigns 'entry' as the entry that follows e in the list.
func (e *icmpPacketEntry) SetNext(elem *icmpPacket) {
	e.next = elem
}

// SetPrev assigns 'entry' as the entry that precedes e in the list.
func (e *icmpPacketEntry) SetPrev(elem *icmpPacket) {
	e.prev = elem
}
