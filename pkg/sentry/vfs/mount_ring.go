package vfs

// Entry is an element in the circular linked list.
//
// +stateify savable
type mountEntry struct {
	next      *mountEntry
	prev      *mountEntry
	container *Mount
}

// Init instantiates an Element to be an item in a ring (circularly-linked
// list).
//
//go:nosplit
func (e *mountEntry) Init(container *Mount) {
	e.next = e
	e.prev = e
	e.container = container
}

// Add adds new to old's ring.
//
//go:nosplit
func (e *mountEntry) Add(new *mountEntry) {
	next := e.next
	prev := e

	next.prev = new
	new.next = next
	new.prev = prev
	e.next = new
}

// Remove removes e from its ring and reinitializes it.
//
//go:nosplit
func (e *mountEntry) Remove() {
	next := e.next
	prev := e.prev

	next.prev = prev
	prev.next = next
	e.Init(e.container)
}

// Empty returns true if there are no other elements in the ring.
//
//go:nosplit
func (e *mountEntry) Empty() bool {
	return e.next == e
}

// Next returns the next containing object pointed to by the list.
//
//go:nosplit
func (e *mountEntry) Next() *Mount {
	return e.next.container
}

// Prev returns the previous containing object pointed to by the list.
//
//go:nosplit
func (e *mountEntry) Prev() *Mount {
	return e.prev.container
}
