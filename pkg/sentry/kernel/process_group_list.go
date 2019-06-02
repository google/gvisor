package kernel

// ElementMapper provides an identity mapping by default.
//
// This can be replaced to provide a struct that maps elements to linker
// objects, if they are not the same. An ElementMapper is not typically
// required if: Linker is left as is, Element is left as is, or Linker and
// Element are the same type.
type processGroupElementMapper struct{}

// linkerFor maps an Element to a Linker.
//
// This default implementation should be inlined.
//
//go:nosplit
func (processGroupElementMapper) linkerFor(elem *ProcessGroup) *ProcessGroup { return elem }

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
type processGroupList struct {
	head *ProcessGroup
	tail *ProcessGroup
}

// Reset resets list l to the empty state.
func (l *processGroupList) Reset() {
	l.head = nil
	l.tail = nil
}

// Empty returns true iff the list is empty.
func (l *processGroupList) Empty() bool {
	return l.head == nil
}

// Front returns the first element of list l or nil.
func (l *processGroupList) Front() *ProcessGroup {
	return l.head
}

// Back returns the last element of list l or nil.
func (l *processGroupList) Back() *ProcessGroup {
	return l.tail
}

// PushFront inserts the element e at the front of list l.
func (l *processGroupList) PushFront(e *ProcessGroup) {
	processGroupElementMapper{}.linkerFor(e).SetNext(l.head)
	processGroupElementMapper{}.linkerFor(e).SetPrev(nil)

	if l.head != nil {
		processGroupElementMapper{}.linkerFor(l.head).SetPrev(e)
	} else {
		l.tail = e
	}

	l.head = e
}

// PushBack inserts the element e at the back of list l.
func (l *processGroupList) PushBack(e *ProcessGroup) {
	processGroupElementMapper{}.linkerFor(e).SetNext(nil)
	processGroupElementMapper{}.linkerFor(e).SetPrev(l.tail)

	if l.tail != nil {
		processGroupElementMapper{}.linkerFor(l.tail).SetNext(e)
	} else {
		l.head = e
	}

	l.tail = e
}

// PushBackList inserts list m at the end of list l, emptying m.
func (l *processGroupList) PushBackList(m *processGroupList) {
	if l.head == nil {
		l.head = m.head
		l.tail = m.tail
	} else if m.head != nil {
		processGroupElementMapper{}.linkerFor(l.tail).SetNext(m.head)
		processGroupElementMapper{}.linkerFor(m.head).SetPrev(l.tail)

		l.tail = m.tail
	}

	m.head = nil
	m.tail = nil
}

// InsertAfter inserts e after b.
func (l *processGroupList) InsertAfter(b, e *ProcessGroup) {
	a := processGroupElementMapper{}.linkerFor(b).Next()
	processGroupElementMapper{}.linkerFor(e).SetNext(a)
	processGroupElementMapper{}.linkerFor(e).SetPrev(b)
	processGroupElementMapper{}.linkerFor(b).SetNext(e)

	if a != nil {
		processGroupElementMapper{}.linkerFor(a).SetPrev(e)
	} else {
		l.tail = e
	}
}

// InsertBefore inserts e before a.
func (l *processGroupList) InsertBefore(a, e *ProcessGroup) {
	b := processGroupElementMapper{}.linkerFor(a).Prev()
	processGroupElementMapper{}.linkerFor(e).SetNext(a)
	processGroupElementMapper{}.linkerFor(e).SetPrev(b)
	processGroupElementMapper{}.linkerFor(a).SetPrev(e)

	if b != nil {
		processGroupElementMapper{}.linkerFor(b).SetNext(e)
	} else {
		l.head = e
	}
}

// Remove removes e from l.
func (l *processGroupList) Remove(e *ProcessGroup) {
	prev := processGroupElementMapper{}.linkerFor(e).Prev()
	next := processGroupElementMapper{}.linkerFor(e).Next()

	if prev != nil {
		processGroupElementMapper{}.linkerFor(prev).SetNext(next)
	} else {
		l.head = next
	}

	if next != nil {
		processGroupElementMapper{}.linkerFor(next).SetPrev(prev)
	} else {
		l.tail = prev
	}
}

// Entry is a default implementation of Linker. Users can add anonymous fields
// of this type to their structs to make them automatically implement the
// methods needed by List.
//
// +stateify savable
type processGroupEntry struct {
	next *ProcessGroup
	prev *ProcessGroup
}

// Next returns the entry that follows e in the list.
func (e *processGroupEntry) Next() *ProcessGroup {
	return e.next
}

// Prev returns the entry that precedes e in the list.
func (e *processGroupEntry) Prev() *ProcessGroup {
	return e.prev
}

// SetNext assigns 'entry' as the entry that follows e in the list.
func (e *processGroupEntry) SetNext(elem *ProcessGroup) {
	e.next = elem
}

// SetPrev assigns 'entry' as the entry that precedes e in the list.
func (e *processGroupEntry) SetPrev(elem *ProcessGroup) {
	e.prev = elem
}
