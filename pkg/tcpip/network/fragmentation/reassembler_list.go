package fragmentation

// ElementMapper provides an identity mapping by default.
//
// This can be replaced to provide a struct that maps elements to linker
// objects, if they are not the same. An ElementMapper is not typically
// required if: Linker is left as is, Element is left as is, or Linker and
// Element are the same type.
type reassemblerElementMapper struct{}

// linkerFor maps an Element to a Linker.
//
// This default implementation should be inlined.
//
//go:nosplit
func (reassemblerElementMapper) linkerFor(elem *reassembler) *reassembler { return elem }

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
type reassemblerList struct {
	head *reassembler
	tail *reassembler
}

// Reset resets list l to the empty state.
func (l *reassemblerList) Reset() {
	l.head = nil
	l.tail = nil
}

// Empty returns true iff the list is empty.
func (l *reassemblerList) Empty() bool {
	return l.head == nil
}

// Front returns the first element of list l or nil.
func (l *reassemblerList) Front() *reassembler {
	return l.head
}

// Back returns the last element of list l or nil.
func (l *reassemblerList) Back() *reassembler {
	return l.tail
}

// PushFront inserts the element e at the front of list l.
func (l *reassemblerList) PushFront(e *reassembler) {
	reassemblerElementMapper{}.linkerFor(e).SetNext(l.head)
	reassemblerElementMapper{}.linkerFor(e).SetPrev(nil)

	if l.head != nil {
		reassemblerElementMapper{}.linkerFor(l.head).SetPrev(e)
	} else {
		l.tail = e
	}

	l.head = e
}

// PushBack inserts the element e at the back of list l.
func (l *reassemblerList) PushBack(e *reassembler) {
	reassemblerElementMapper{}.linkerFor(e).SetNext(nil)
	reassemblerElementMapper{}.linkerFor(e).SetPrev(l.tail)

	if l.tail != nil {
		reassemblerElementMapper{}.linkerFor(l.tail).SetNext(e)
	} else {
		l.head = e
	}

	l.tail = e
}

// PushBackList inserts list m at the end of list l, emptying m.
func (l *reassemblerList) PushBackList(m *reassemblerList) {
	if l.head == nil {
		l.head = m.head
		l.tail = m.tail
	} else if m.head != nil {
		reassemblerElementMapper{}.linkerFor(l.tail).SetNext(m.head)
		reassemblerElementMapper{}.linkerFor(m.head).SetPrev(l.tail)

		l.tail = m.tail
	}

	m.head = nil
	m.tail = nil
}

// InsertAfter inserts e after b.
func (l *reassemblerList) InsertAfter(b, e *reassembler) {
	a := reassemblerElementMapper{}.linkerFor(b).Next()
	reassemblerElementMapper{}.linkerFor(e).SetNext(a)
	reassemblerElementMapper{}.linkerFor(e).SetPrev(b)
	reassemblerElementMapper{}.linkerFor(b).SetNext(e)

	if a != nil {
		reassemblerElementMapper{}.linkerFor(a).SetPrev(e)
	} else {
		l.tail = e
	}
}

// InsertBefore inserts e before a.
func (l *reassemblerList) InsertBefore(a, e *reassembler) {
	b := reassemblerElementMapper{}.linkerFor(a).Prev()
	reassemblerElementMapper{}.linkerFor(e).SetNext(a)
	reassemblerElementMapper{}.linkerFor(e).SetPrev(b)
	reassemblerElementMapper{}.linkerFor(a).SetPrev(e)

	if b != nil {
		reassemblerElementMapper{}.linkerFor(b).SetNext(e)
	} else {
		l.head = e
	}
}

// Remove removes e from l.
func (l *reassemblerList) Remove(e *reassembler) {
	prev := reassemblerElementMapper{}.linkerFor(e).Prev()
	next := reassemblerElementMapper{}.linkerFor(e).Next()

	if prev != nil {
		reassemblerElementMapper{}.linkerFor(prev).SetNext(next)
	} else {
		l.head = next
	}

	if next != nil {
		reassemblerElementMapper{}.linkerFor(next).SetPrev(prev)
	} else {
		l.tail = prev
	}
}

// Entry is a default implementation of Linker. Users can add anonymous fields
// of this type to their structs to make them automatically implement the
// methods needed by List.
//
// +stateify savable
type reassemblerEntry struct {
	next *reassembler
	prev *reassembler
}

// Next returns the entry that follows e in the list.
func (e *reassemblerEntry) Next() *reassembler {
	return e.next
}

// Prev returns the entry that precedes e in the list.
func (e *reassemblerEntry) Prev() *reassembler {
	return e.prev
}

// SetNext assigns 'entry' as the entry that follows e in the list.
func (e *reassemblerEntry) SetNext(elem *reassembler) {
	e.next = elem
}

// SetPrev assigns 'entry' as the entry that precedes e in the list.
func (e *reassemblerEntry) SetPrev(elem *reassembler) {
	e.prev = elem
}
