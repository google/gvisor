package kernel

// ElementMapper provides an identity mapping by default.
//
// This can be replaced to provide a struct that maps elements to linker
// objects, if they are not the same. An ElementMapper is not typically
// required if: Linker is left as is, Element is left as is, or Linker and
// Element are the same type.
type taskElementMapper struct{}

// linkerFor maps an Element to a Linker.
//
// This default implementation should be inlined.
//
//go:nosplit
func (taskElementMapper) linkerFor(elem *Task) *Task { return elem }

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
type taskList struct {
	head *Task
	tail *Task
}

// Reset resets list l to the empty state.
func (l *taskList) Reset() {
	l.head = nil
	l.tail = nil
}

// Empty returns true iff the list is empty.
func (l *taskList) Empty() bool {
	return l.head == nil
}

// Front returns the first element of list l or nil.
func (l *taskList) Front() *Task {
	return l.head
}

// Back returns the last element of list l or nil.
func (l *taskList) Back() *Task {
	return l.tail
}

// PushFront inserts the element e at the front of list l.
func (l *taskList) PushFront(e *Task) {
	taskElementMapper{}.linkerFor(e).SetNext(l.head)
	taskElementMapper{}.linkerFor(e).SetPrev(nil)

	if l.head != nil {
		taskElementMapper{}.linkerFor(l.head).SetPrev(e)
	} else {
		l.tail = e
	}

	l.head = e
}

// PushBack inserts the element e at the back of list l.
func (l *taskList) PushBack(e *Task) {
	taskElementMapper{}.linkerFor(e).SetNext(nil)
	taskElementMapper{}.linkerFor(e).SetPrev(l.tail)

	if l.tail != nil {
		taskElementMapper{}.linkerFor(l.tail).SetNext(e)
	} else {
		l.head = e
	}

	l.tail = e
}

// PushBackList inserts list m at the end of list l, emptying m.
func (l *taskList) PushBackList(m *taskList) {
	if l.head == nil {
		l.head = m.head
		l.tail = m.tail
	} else if m.head != nil {
		taskElementMapper{}.linkerFor(l.tail).SetNext(m.head)
		taskElementMapper{}.linkerFor(m.head).SetPrev(l.tail)

		l.tail = m.tail
	}

	m.head = nil
	m.tail = nil
}

// InsertAfter inserts e after b.
func (l *taskList) InsertAfter(b, e *Task) {
	a := taskElementMapper{}.linkerFor(b).Next()
	taskElementMapper{}.linkerFor(e).SetNext(a)
	taskElementMapper{}.linkerFor(e).SetPrev(b)
	taskElementMapper{}.linkerFor(b).SetNext(e)

	if a != nil {
		taskElementMapper{}.linkerFor(a).SetPrev(e)
	} else {
		l.tail = e
	}
}

// InsertBefore inserts e before a.
func (l *taskList) InsertBefore(a, e *Task) {
	b := taskElementMapper{}.linkerFor(a).Prev()
	taskElementMapper{}.linkerFor(e).SetNext(a)
	taskElementMapper{}.linkerFor(e).SetPrev(b)
	taskElementMapper{}.linkerFor(a).SetPrev(e)

	if b != nil {
		taskElementMapper{}.linkerFor(b).SetNext(e)
	} else {
		l.head = e
	}
}

// Remove removes e from l.
func (l *taskList) Remove(e *Task) {
	prev := taskElementMapper{}.linkerFor(e).Prev()
	next := taskElementMapper{}.linkerFor(e).Next()

	if prev != nil {
		taskElementMapper{}.linkerFor(prev).SetNext(next)
	} else {
		l.head = next
	}

	if next != nil {
		taskElementMapper{}.linkerFor(next).SetPrev(prev)
	} else {
		l.tail = prev
	}
}

// Entry is a default implementation of Linker. Users can add anonymous fields
// of this type to their structs to make them automatically implement the
// methods needed by List.
//
// +stateify savable
type taskEntry struct {
	next *Task
	prev *Task
}

// Next returns the entry that follows e in the list.
func (e *taskEntry) Next() *Task {
	return e.next
}

// Prev returns the entry that precedes e in the list.
func (e *taskEntry) Prev() *Task {
	return e.prev
}

// SetNext assigns 'entry' as the entry that follows e in the list.
func (e *taskEntry) SetNext(elem *Task) {
	e.next = elem
}

// SetPrev assigns 'entry' as the entry that precedes e in the list.
func (e *taskEntry) SetPrev(elem *Task) {
	e.prev = elem
}
