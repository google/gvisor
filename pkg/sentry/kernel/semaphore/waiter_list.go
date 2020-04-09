package semaphore

// ElementMapper provides an identity mapping by default.
//
// This can be replaced to provide a struct that maps elements to linker
// objects, if they are not the same. An ElementMapper is not typically
// required if: Linker is left as is, Element is left as is, or Linker and
// Element are the same type.
type waiterElementMapper struct{}

// linkerFor maps an Element to a Linker.
//
// This default implementation should be inlined.
//
//go:nosplit
func (waiterElementMapper) linkerFor(elem *waiter) *waiter { return elem }

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
type waiterList struct {
	head *waiter
	tail *waiter
}

// Reset resets list l to the empty state.
func (l *waiterList) Reset() {
	l.head = nil
	l.tail = nil
}

// Empty returns true iff the list is empty.
func (l *waiterList) Empty() bool {
	return l.head == nil
}

// Front returns the first element of list l or nil.
func (l *waiterList) Front() *waiter {
	return l.head
}

// Back returns the last element of list l or nil.
func (l *waiterList) Back() *waiter {
	return l.tail
}

// Len returns the number of elements in the list.
//
// NOTE: This is an O(n) operation.
func (l *waiterList) Len() (count int) {
	for e := l.Front(); e != nil; e = e.Next() {
		count++
	}
	return count
}

// PushFront inserts the element e at the front of list l.
func (l *waiterList) PushFront(e *waiter) {
	linker := waiterElementMapper{}.linkerFor(e)
	linker.SetNext(l.head)
	linker.SetPrev(nil)
	if l.head != nil {
		waiterElementMapper{}.linkerFor(l.head).SetPrev(e)
	} else {
		l.tail = e
	}

	l.head = e
}

// PushBack inserts the element e at the back of list l.
func (l *waiterList) PushBack(e *waiter) {
	linker := waiterElementMapper{}.linkerFor(e)
	linker.SetNext(nil)
	linker.SetPrev(l.tail)
	if l.tail != nil {
		waiterElementMapper{}.linkerFor(l.tail).SetNext(e)
	} else {
		l.head = e
	}

	l.tail = e
}

// PushBackList inserts list m at the end of list l, emptying m.
func (l *waiterList) PushBackList(m *waiterList) {
	if l.head == nil {
		l.head = m.head
		l.tail = m.tail
	} else if m.head != nil {
		waiterElementMapper{}.linkerFor(l.tail).SetNext(m.head)
		waiterElementMapper{}.linkerFor(m.head).SetPrev(l.tail)

		l.tail = m.tail
	}
	m.head = nil
	m.tail = nil
}

// InsertAfter inserts e after b.
func (l *waiterList) InsertAfter(b, e *waiter) {
	bLinker := waiterElementMapper{}.linkerFor(b)
	eLinker := waiterElementMapper{}.linkerFor(e)

	a := bLinker.Next()

	eLinker.SetNext(a)
	eLinker.SetPrev(b)
	bLinker.SetNext(e)

	if a != nil {
		waiterElementMapper{}.linkerFor(a).SetPrev(e)
	} else {
		l.tail = e
	}
}

// InsertBefore inserts e before a.
func (l *waiterList) InsertBefore(a, e *waiter) {
	aLinker := waiterElementMapper{}.linkerFor(a)
	eLinker := waiterElementMapper{}.linkerFor(e)

	b := aLinker.Prev()
	eLinker.SetNext(a)
	eLinker.SetPrev(b)
	aLinker.SetPrev(e)

	if b != nil {
		waiterElementMapper{}.linkerFor(b).SetNext(e)
	} else {
		l.head = e
	}
}

// Remove removes e from l.
func (l *waiterList) Remove(e *waiter) {
	linker := waiterElementMapper{}.linkerFor(e)
	prev := linker.Prev()
	next := linker.Next()

	if prev != nil {
		waiterElementMapper{}.linkerFor(prev).SetNext(next)
	} else {
		l.head = next
	}

	if next != nil {
		waiterElementMapper{}.linkerFor(next).SetPrev(prev)
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
type waiterEntry struct {
	next *waiter
	prev *waiter
}

// Next returns the entry that follows e in the list.
func (e *waiterEntry) Next() *waiter {
	return e.next
}

// Prev returns the entry that precedes e in the list.
func (e *waiterEntry) Prev() *waiter {
	return e.prev
}

// SetNext assigns 'entry' as the entry that follows e in the list.
func (e *waiterEntry) SetNext(elem *waiter) {
	e.next = elem
}

// SetPrev assigns 'entry' as the entry that precedes e in the list.
func (e *waiterEntry) SetPrev(elem *waiter) {
	e.prev = elem
}
