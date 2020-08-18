package tcp

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
type rackSegmentList struct {
	head *segment
	tail *segment
}

// Reset resets list l to the empty state.
func (l *rackSegmentList) Reset() {
	l.head = nil
	l.tail = nil
}

// Empty returns true iff the list is empty.
func (l *rackSegmentList) Empty() bool {
	return l.head == nil
}

// Front returns the first element of list l or nil.
func (l *rackSegmentList) Front() *segment {
	return l.head
}

// Back returns the last element of list l or nil.
func (l *rackSegmentList) Back() *segment {
	return l.tail
}

// Len returns the number of elements in the list.
//
// NOTE: This is an O(n) operation.
func (l *rackSegmentList) Len() (count int) {
	for e := l.Front(); e != nil; e = (rackSegmentMapper{}.linkerFor(e)).Next() {
		count++
	}
	return count
}

// PushFront inserts the element e at the front of list l.
func (l *rackSegmentList) PushFront(e *segment) {
	linker := rackSegmentMapper{}.linkerFor(e)
	linker.SetNext(l.head)
	linker.SetPrev(nil)
	if l.head != nil {
		rackSegmentMapper{}.linkerFor(l.head).SetPrev(e)
	} else {
		l.tail = e
	}

	l.head = e
}

// PushBack inserts the element e at the back of list l.
func (l *rackSegmentList) PushBack(e *segment) {
	linker := rackSegmentMapper{}.linkerFor(e)
	linker.SetNext(nil)
	linker.SetPrev(l.tail)
	if l.tail != nil {
		rackSegmentMapper{}.linkerFor(l.tail).SetNext(e)
	} else {
		l.head = e
	}

	l.tail = e
}

// PushBackList inserts list m at the end of list l, emptying m.
func (l *rackSegmentList) PushBackList(m *rackSegmentList) {
	if l.head == nil {
		l.head = m.head
		l.tail = m.tail
	} else if m.head != nil {
		rackSegmentMapper{}.linkerFor(l.tail).SetNext(m.head)
		rackSegmentMapper{}.linkerFor(m.head).SetPrev(l.tail)

		l.tail = m.tail
	}
	m.head = nil
	m.tail = nil
}

// InsertAfter inserts e after b.
func (l *rackSegmentList) InsertAfter(b, e *segment) {
	bLinker := rackSegmentMapper{}.linkerFor(b)
	eLinker := rackSegmentMapper{}.linkerFor(e)

	a := bLinker.Next()

	eLinker.SetNext(a)
	eLinker.SetPrev(b)
	bLinker.SetNext(e)

	if a != nil {
		rackSegmentMapper{}.linkerFor(a).SetPrev(e)
	} else {
		l.tail = e
	}
}

// InsertBefore inserts e before a.
func (l *rackSegmentList) InsertBefore(a, e *segment) {
	aLinker := rackSegmentMapper{}.linkerFor(a)
	eLinker := rackSegmentMapper{}.linkerFor(e)

	b := aLinker.Prev()
	eLinker.SetNext(a)
	eLinker.SetPrev(b)
	aLinker.SetPrev(e)

	if b != nil {
		rackSegmentMapper{}.linkerFor(b).SetNext(e)
	} else {
		l.head = e
	}
}

// Remove removes e from l.
func (l *rackSegmentList) Remove(e *segment) {
	linker := rackSegmentMapper{}.linkerFor(e)
	prev := linker.Prev()
	next := linker.Next()

	if prev != nil {
		rackSegmentMapper{}.linkerFor(prev).SetNext(next)
	} else if l.head == e {
		l.head = next
	}

	if next != nil {
		rackSegmentMapper{}.linkerFor(next).SetPrev(prev)
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
type rackSegmentEntry struct {
	next *segment
	prev *segment
}

// Next returns the entry that follows e in the list.
func (e *rackSegmentEntry) Next() *segment {
	return e.next
}

// Prev returns the entry that precedes e in the list.
func (e *rackSegmentEntry) Prev() *segment {
	return e.prev
}

// SetNext assigns 'entry' as the entry that follows e in the list.
func (e *rackSegmentEntry) SetNext(elem *segment) {
	e.next = elem
}

// SetPrev assigns 'entry' as the entry that precedes e in the list.
func (e *rackSegmentEntry) SetPrev(elem *segment) {
	e.prev = elem
}
