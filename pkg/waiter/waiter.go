// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package waiter provides the implementation of a wait queue, where waiters can
// be enqueued to be notified when an event of interest happens.
//
// Becoming readable and/or writable are examples of events. Waiters are
// expected to use a pattern similar to this to make a blocking function out of
// a non-blocking one:
//
//	func (o *object) blockingRead(...) error {
//		err := o.nonBlockingRead(...)
//		if err != ErrAgain {
//			// Completed with no need to wait!
//			return err
//		}
//
//		e := createOrGetWaiterEntry(...)
//		o.EventRegister(&e, waiter.EventIn)
//		defer o.EventUnregister(&e)
//
//		// We need to try to read again after registration because the
//		// object may have become readable between the last attempt to
//		// read and read registration.
//		err = o.nonBlockingRead(...)
//		for err == ErrAgain {
//			wait()
//			err = o.nonBlockingRead(...)
//		}
//
//		return err
//	}
//
// Another goroutine needs to notify waiters when events happen. For example:
//
//	func (o *object) Write(...) ... {
//		// Do write work.
//		[...]
//
//		if oldDataAvailableSize == 0 && dataAvailableSize > 0 {
//			// If no data was available and now some data is
//			// available, the object became readable, so notify
//			// potential waiters about this.
//			o.Notify(waiter.EventIn)
//		}
//	}
package waiter

import (
	"sync"

	"gvisor.googlesource.com/gvisor/pkg/ilist"
)

// EventMask represents io events as used in the poll() syscall.
type EventMask uint16

// Events that waiters can wait on. The meaning is the same as those in the
// poll() syscall.
const (
	EventIn   EventMask = 0x01 // syscall.EPOLLIN
	EventPri  EventMask = 0x02 // syscall.EPOLLPRI
	EventOut  EventMask = 0x04 // syscall.EPOLLOUT
	EventErr  EventMask = 0x08 // syscall.EPOLLERR
	EventHUp  EventMask = 0x10 // syscall.EPOLLHUP
	EventNVal EventMask = 0x20 // Not defined in syscall.
)

// Waitable contains the methods that need to be implemented by waitable
// objects.
type Waitable interface {
	// Readiness returns what the object is currently ready for. If it's
	// not ready for a desired purpose, the caller may use EventRegister and
	// EventUnregister to get notifications once the object becomes ready.
	//
	// Implementations should allow for events like EventHUp and EventErr
	// to be returned regardless of whether they are in the input EventMask.
	Readiness(mask EventMask) EventMask

	// EventRegister registers the given waiter entry to receive
	// notifications when an event occurs that makes the object ready for
	// at least one of the events in mask.
	EventRegister(e *Entry, mask EventMask)

	// EventUnregister unregisters a waiter entry previously registered with
	// EventRegister().
	EventUnregister(e *Entry)
}

// EntryCallback provides a notify callback.
type EntryCallback interface {
	// Callback is the function to be called when the waiter entry is
	// notified. It is responsible for doing whatever is needed to wake up
	// the waiter.
	//
	// The callback is supposed to perform minimal work, and cannot call
	// any method on the queue itself because it will be locked while the
	// callback is running.
	Callback(e *Entry)
}

// Entry represents a waiter that can be add to the a wait queue. It can
// only be in one queue at a time, and is added "intrusively" to the queue with
// no extra memory allocations.
type Entry struct {
	// Context stores any state the waiter may wish to store in the entry
	// itself, which may be used at wake up time.
	//
	// Note that use of this field is optional and state may alternatively be
	// stored in the callback itself.
	Context interface{}

	Callback EntryCallback

	// The following fields are protected by the queue lock.
	mask EventMask
	ilist.Entry
}

type channelCallback struct{}

// Callback implements EntryCallback.Callback.
func (*channelCallback) Callback(e *Entry) {
	ch := e.Context.(chan struct{})
	select {
	case ch <- struct{}{}:
	default:
	}
}

// NewChannelEntry initializes a new Entry that does a non-blocking write to a
// struct{} channel when the callback is called. It returns the new Entry
// instance and the channel being used.
//
// If a channel isn't specified (i.e., if "c" is nil), then NewChannelEntry
// allocates a new channel.
func NewChannelEntry(c chan struct{}) (Entry, chan struct{}) {
	if c == nil {
		c = make(chan struct{}, 1)
	}

	return Entry{Context: c, Callback: &channelCallback{}}, c
}

// Queue represents the wait queue where waiters can be added and
// notifiers can notify them when events happen.
//
// The zero value for waiter.Queue is an empty queue ready for use.
type Queue struct {
	list ilist.List   `state:"zerovalue"`
	mu   sync.RWMutex `state:"nosave"`
}

// EventRegister adds a waiter to the wait queue; the waiter will be notified
// when at least one of the events specified in mask happens.
func (q *Queue) EventRegister(e *Entry, mask EventMask) {
	q.mu.Lock()
	e.mask = mask
	q.list.PushBack(e)
	q.mu.Unlock()
}

// EventUnregister removes the given waiter entry from the wait queue.
func (q *Queue) EventUnregister(e *Entry) {
	q.mu.Lock()
	q.list.Remove(e)
	q.mu.Unlock()
}

// Notify notifies all waiters in the queue whose masks have at least one bit
// in common with the notification mask.
func (q *Queue) Notify(mask EventMask) {
	q.mu.RLock()
	for it := q.list.Front(); it != nil; it = it.Next() {
		e := it.(*Entry)
		if mask&e.mask != 0 {
			e.Callback.Callback(e)
		}
	}
	q.mu.RUnlock()
}

// Events returns the set of events being waited on. It is the union of the
// masks of all registered entries.
func (q *Queue) Events() EventMask {
	ret := EventMask(0)

	q.mu.RLock()
	for it := q.list.Front(); it != nil; it = it.Next() {
		e := it.(*Entry)
		ret |= e.mask
	}
	q.mu.RUnlock()

	return ret
}

// IsEmpty returns if the wait queue is empty or not.
func (q *Queue) IsEmpty() bool {
	q.mu.Lock()
	defer q.mu.Unlock()

	return q.list.Front() == nil
}

// AlwaysReady implements the Waitable interface but is always ready. Embedding
// this struct into another struct makes it implement the boilerplate empty
// functions automatically.
type AlwaysReady struct {
}

// Readiness always returns the input mask because this object is always ready.
func (*AlwaysReady) Readiness(mask EventMask) EventMask {
	return mask
}

// EventRegister doesn't do anything because this object doesn't need to issue
// notifications because its readiness never changes.
func (*AlwaysReady) EventRegister(*Entry, EventMask) {
}

// EventUnregister doesn't do anything because this object doesn't need to issue
// notifications because its readiness never changes.
func (*AlwaysReady) EventUnregister(e *Entry) {
}
