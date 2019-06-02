package fs

// ElementMapper provides an identity mapping by default.
//
// This can be replaced to provide a struct that maps elements to linker
// objects, if they are not the same. An ElementMapper is not typically
// required if: Linker is left as is, Element is left as is, or Linker and
// Element are the same type.
type direntElementMapper struct{}

// linkerFor maps an Element to a Linker.
//
// This default implementation should be inlined.
//
//go:nosplit
func (direntElementMapper) linkerFor(elem *Dirent) *Dirent { return elem }

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
type direntList struct {
	head *Dirent
	tail *Dirent
}

// Reset resets list l to the empty state.
func (l *direntList) Reset() {
	l.head = nil
	l.tail = nil
}

// Empty returns true iff the list is empty.
func (l *direntList) Empty() bool {
	return l.head == nil
}

// Front returns the first element of list l or nil.
func (l *direntList) Front() *Dirent {
	return l.head
}

// Back returns the last element of list l or nil.
func (l *direntList) Back() *Dirent {
	return l.tail
}

// PushFront inserts the element e at the front of list l.
func (l *direntList) PushFront(e *Dirent) {
	direntElementMapper{}.linkerFor(e).SetNext(l.head)
	direntElementMapper{}.linkerFor(e).SetPrev(nil)

	if l.head != nil {
		direntElementMapper{}.linkerFor(l.head).SetPrev(e)
	} else {
		l.tail = e
	}

	l.head = e
}

// PushBack inserts the element e at the back of list l.
func (l *direntList) PushBack(e *Dirent) {
	direntElementMapper{}.linkerFor(e).SetNext(nil)
	direntElementMapper{}.linkerFor(e).SetPrev(l.tail)

	if l.tail != nil {
		direntElementMapper{}.linkerFor(l.tail).SetNext(e)
	} else {
		l.head = e
	}

	l.tail = e
}

// PushBackList inserts list m at the end of list l, emptying m.
func (l *direntList) PushBackList(m *direntList) {
	if l.head == nil {
		l.head = m.head
		l.tail = m.tail
	} else if m.head != nil {
		direntElementMapper{}.linkerFor(l.tail).SetNext(m.head)
		direntElementMapper{}.linkerFor(m.head).SetPrev(l.tail)

		l.tail = m.tail
	}

	m.head = nil
	m.tail = nil
}

// InsertAfter inserts e after b.
func (l *direntList) InsertAfter(b, e *Dirent) {
	a := direntElementMapper{}.linkerFor(b).Next()
	direntElementMapper{}.linkerFor(e).SetNext(a)
	direntElementMapper{}.linkerFor(e).SetPrev(b)
	direntElementMapper{}.linkerFor(b).SetNext(e)

	if a != nil {
		direntElementMapper{}.linkerFor(a).SetPrev(e)
	} else {
		l.tail = e
	}
}

// InsertBefore inserts e before a.
func (l *direntList) InsertBefore(a, e *Dirent) {
	b := direntElementMapper{}.linkerFor(a).Prev()
	direntElementMapper{}.linkerFor(e).SetNext(a)
	direntElementMapper{}.linkerFor(e).SetPrev(b)
	direntElementMapper{}.linkerFor(a).SetPrev(e)

	if b != nil {
		direntElementMapper{}.linkerFor(b).SetNext(e)
	} else {
		l.head = e
	}
}

// Remove removes e from l.
func (l *direntList) Remove(e *Dirent) {
	prev := direntElementMapper{}.linkerFor(e).Prev()
	next := direntElementMapper{}.linkerFor(e).Next()

	if prev != nil {
		direntElementMapper{}.linkerFor(prev).SetNext(next)
	} else {
		l.head = next
	}

	if next != nil {
		direntElementMapper{}.linkerFor(next).SetPrev(prev)
	} else {
		l.tail = prev
	}
}

// Entry is a default implementation of Linker. Users can add anonymous fields
// of this type to their structs to make them automatically implement the
// methods needed by List.
//
// +stateify savable
type direntEntry struct {
	next *Dirent
	prev *Dirent
}

// Next returns the entry that follows e in the list.
func (e *direntEntry) Next() *Dirent {
	return e.next
}

// Prev returns the entry that precedes e in the list.
func (e *direntEntry) Prev() *Dirent {
	return e.prev
}

// SetNext assigns 'entry' as the entry that follows e in the list.
func (e *direntEntry) SetNext(elem *Dirent) {
	e.next = elem
}

// SetPrev assigns 'entry' as the entry that precedes e in the list.
func (e *direntEntry) SetPrev(elem *Dirent) {
	e.prev = elem
}
