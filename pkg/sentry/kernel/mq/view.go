// Copyright 2021 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mq

import (
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
)

// View is a view into a message queue. Views should only be used in file
// descriptions, but not inodes, because we use inodes to retreive the actual
// queue, and only FDs are responsible for providing user functionality.
type View interface {
	// Send adds a given message to the queue, and returns an error if sending
	// fails. See mq_timedsend(2).
	Send(ctx context.Context, msg Message, b Blocker, timeout time.Duration) error

	// Receive returns the message with the highest priority from the queue. See
	// mq_timedreceive(2).
	Receive(ctx context.Context, b Blocker, timeout time.Duration) (*Message, error)

	// Attr returns the view's attributes. See mq_getattr(3).
	Attr() *linux.MqAttr

	// Set sets the view's block flag. See mq_setattr(3).
	Set(block bool)

	// Queue returns the queue backing this view, which provides general queue
	// functions.
	Queue() *Queue
}

// ReaderWriter provides a send and receive view into a queue.
type ReaderWriter struct {
	*viewImpl
}

// Reader provides a send-only view into a queue.
type Reader struct {
	*viewImpl
}

// Send implements View.Send. It disables sending for read-only views.
func (r Reader) Send(ctx context.Context, msg Message, b Blocker, timeout time.Duration) error {
	return linuxerr.EBADF
}

// Writer provides a receive-only view into a queue.
type Writer struct {
	*viewImpl
}

// Receive implements View.Receive. It disables receiving for write-only views.
func (w Writer) Receive(ctx context.Context, b Blocker, timeout time.Duration) (*Message, error) {
	return nil, linuxerr.EBADF
}

// viewImpl implements View interface and should be embedded into different
// views.
type viewImpl struct {
	// q is the queue backing this view.
	q *Queue

	// block indicates whether or not the view is blocking, and is passed down
	// Queue's functions. Whether or not functions block is a property of a
	// View, not a Queue, as the same queue can be used as blocking or
	// non-blocking.
	block bool
}

// NewView creates a new view into a queue and returns it.
func NewView(q *Queue, access AccessType, block bool) (View, error) {
	switch access {
	case ReadWrite:
		return ReaderWriter{&viewImpl{q: q, block: block}}, nil
	case WriteOnly:
		return Writer{&viewImpl{q: q, block: block}}, nil
	case ReadOnly:
		return Reader{&viewImpl{q: q, block: block}}, nil
	default:
		// This case can't happen, due to O_RDONLY flag being 0 and O_WRONLY
		// being 1, so one of them must be true.
		return nil, linuxerr.EINVAL
	}
}

// Send implements View.Send.
func (i *viewImpl) Send(ctx context.Context, msg Message, b Blocker, timeout time.Duration) error {
	return i.q.send(ctx, msg, b, timeout, i.block)
}

// Receive implements View.Receive.
func (i *viewImpl) Receive(ctx context.Context, b Blocker, timeout time.Duration) (*Message, error) {
	return i.q.receive(ctx, b, timeout, i.block)
}

// Attr implements View.Attr.
func (i *viewImpl) Attr() *linux.MqAttr {
	return i.q.Attr(i.block)
}

// Set implements View.Set.
func (i *viewImpl) Set(block bool) {
	i.q.mu.Lock()
	defer i.q.mu.Unlock()

	i.block = block
}

// Queue implements View.Queue.
func (i *viewImpl) Queue() *Queue {
	return i.q
}
