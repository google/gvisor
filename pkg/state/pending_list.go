package state

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
type pendingList struct {
	head *objectEncodeState
	tail *objectEncodeState
}

// Reset resets list l to the empty state.
func (l *pendingList) Reset() {
	l.head = nil
	l.tail = nil
}

// Empty returns true iff the list is empty.
func (l *pendingList) Empty() bool {
	return l.head == nil
}

// Front returns the first element of list l or nil.
func (l *pendingList) Front() *objectEncodeState {
	return l.head
}

// Back returns the last element of list l or nil.
func (l *pendingList) Back() *objectEncodeState {
	return l.tail
}

// Len returns the number of elements in the list.
//
// NOTE: This is an O(n) operation.
func (l *pendingList) Len() (count int) {
	for e := l.Front(); e != nil; e = (pendingMapper{}.linkerFor(e)).Next() {
		count++
	}
	return count
}

// PushFront inserts the element e at the front of list l.
func (l *pendingList) PushFront(e *objectEncodeState) {
	linker := pendingMapper{}.linkerFor(e)
	linker.SetNext(l.head)
	linker.SetPrev(nil)
	if l.head != nil {
		pendingMapper{}.linkerFor(l.head).SetPrev(e)
	} else {
		l.tail = e
	}

	l.head = e
}

// PushBack inserts the element e at the back of list l.
func (l *pendingList) PushBack(e *objectEncodeState) {
	linker := pendingMapper{}.linkerFor(e)
	linker.SetNext(nil)
	linker.SetPrev(l.tail)
	if l.tail != nil {
		pendingMapper{}.linkerFor(l.tail).SetNext(e)
	} else {
		l.head = e
	}

	l.tail = e
}

// PushBackList inserts list m at the end of list l, emptying m.
func (l *pendingList) PushBackList(m *pendingList) {
	if l.head == nil {
		l.head = m.head
		l.tail = m.tail
	} else if m.head != nil {
		pendingMapper{}.linkerFor(l.tail).SetNext(m.head)
		pendingMapper{}.linkerFor(m.head).SetPrev(l.tail)

		l.tail = m.tail
	}
	m.head = nil
	m.tail = nil
}

// InsertAfter inserts e after b.
func (l *pendingList) InsertAfter(b, e *objectEncodeState) {
	bLinker := pendingMapper{}.linkerFor(b)
	eLinker := pendingMapper{}.linkerFor(e)

	a := bLinker.Next()

	eLinker.SetNext(a)
	eLinker.SetPrev(b)
	bLinker.SetNext(e)

	if a != nil {
		pendingMapper{}.linkerFor(a).SetPrev(e)
	} else {
		l.tail = e
	}
}

// InsertBefore inserts e before a.
func (l *pendingList) InsertBefore(a, e *objectEncodeState) {
	aLinker := pendingMapper{}.linkerFor(a)
	eLinker := pendingMapper{}.linkerFor(e)

	b := aLinker.Prev()
	eLinker.SetNext(a)
	eLinker.SetPrev(b)
	aLinker.SetPrev(e)

	if b != nil {
		pendingMapper{}.linkerFor(b).SetNext(e)
	} else {
		l.head = e
	}
}

// Remove removes e from l.
func (l *pendingList) Remove(e *objectEncodeState) {
	linker := pendingMapper{}.linkerFor(e)
	prev := linker.Prev()
	next := linker.Next()

	if prev != nil {
		pendingMapper{}.linkerFor(prev).SetNext(next)
	} else if l.head == e {
		l.head = next
	}

	if next != nil {
		pendingMapper{}.linkerFor(next).SetPrev(prev)
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
type pendingEntry struct {
	next *objectEncodeState
	prev *objectEncodeState
}

// Next returns the entry that follows e in the list.
func (e *pendingEntry) Next() *objectEncodeState {
	return e.next
}

// Prev returns the entry that precedes e in the list.
func (e *pendingEntry) Prev() *objectEncodeState {
	return e.prev
}

// SetNext assigns 'entry' as the entry that follows e in the list.
func (e *pendingEntry) SetNext(elem *objectEncodeState) {
	e.next = elem
}

// SetPrev assigns 'entry' as the entry that precedes e in the list.
func (e *pendingEntry) SetPrev(elem *objectEncodeState) {
	e.prev = elem
}
