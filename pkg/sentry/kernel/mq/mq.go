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

// Package mq provides an implementation for POSIX message queues.
package mq

import (
	"bytes"
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	MaxName     = 255                   // Maximum size for a queue name.
	maxPriority = linux.MQ_PRIO_MAX - 1 // Highest possible message priority.
)

// Registry is a POSIX message queue registry.
//
// Unlike SysV utilities, Registry is not map-based. It uses a provided
// RegistryImpl backed by a virtual filesystem to implement registry operations.
//
// +stateify savable
type Registry struct {
	// impl is an implementation of several message queue utilities needed by
	// the registry. impl should be provided by mqfs.
	impl RegistryImpl
}

// RegistryImpl defines utilities needed by a Registry to provide actual
// registry implementation. It works mainly as an abstraction layer used by
// Registry to avoid dealing directly with the filesystem. RegistryImpl should
// be implemented by mqfs and provided to Registry at initialization.
type RegistryImpl interface {
	// Get searchs for a queue with the given name, if it exists, the queue is
	// used to create a new FD, return it and return true. If the queue  doesn't
	// exist, return false and no error. An error is returned if creation fails.
	Get(ctx context.Context, name string, rOnly, wOnly, readWrite, block bool, flags uint32) (*vfs.FileDescription, bool, error)

	// New creates a new inode and file description using the given queue,
	// inserts the inode into the filesystem tree using the given name, and
	// returns the file description. An error is returned if creation fails, or
	// if the name already exists.
	New(ctx context.Context, name string, q *Queue, rOnly, wOnly, readWrite, block bool, perm linux.FileMode, flags uint32) (*vfs.FileDescription, error)

	// Unlink removes the queue with given name from the registry, and returns
	// an error if the name doesn't exist.
	Unlink(ctx context.Context, name string) error

	// Destroy destroys the registry.
	Destroy(context.Context)
}

// NewRegistry returns a new, initialized message queue registry. NewRegistry
// should be called when a new message queue filesystem is created, once per
// IPCNamespace.
func NewRegistry(impl RegistryImpl) *Registry {
	return &Registry{
		impl: impl,
	}
}

// Destroy destroys the registry and releases all held references.
func (r *Registry) Destroy(ctx context.Context) {
	r.impl.Destroy(ctx)
}

// Impl returns RegistryImpl inside r.
func (r *Registry) Impl() RegistryImpl {
	return r.impl
}

// Queue represents a POSIX message queue.
//
// +stateify savable
type Queue struct {
	// owner is the registry's owner. Immutable.
	owner fs.FileOwner

	// perms is the registry's access permissions. Immutable.
	perms fs.FilePermissions

	// mu protects all the fields below.
	mu sync.Mutex `state:"nosave"`

	// senders is a queue of currently blocked senders. Senders are notified
	// when space isi available in the queue for a new message.
	senders waiter.Queue

	// receivers is a queue of currently blocked receivers. Receivers are
	// notified when a new message is inserted in the queue.
	receivers waiter.Queue

	// messages is a list of messages currently in the queue.
	messages msgList

	// subscriber represents a task registered to receive async notification
	// from this queue.
	subscriber *Subscriber

	// nonBlock is true if this queue is non-blocking.
	nonBlock bool

	// messageCount is the number of messages currently in the queue.
	messageCount int64

	// maxMessageCount is the maximum number of messages that the queue can
	// hold.
	maxMessageCount int64

	// maxMessageSize is the maximum size of a message held by the queue.
	maxMessageSize uint64

	// byteCount is the number of bytes of data in all messages in the queue.
	byteCount uint64
}

// View is a view into a message queue. Views should only be used in file
// descriptions, but not inodes, because we use inodes to retreive the actual
// queue, and only FDs are responsible for providing user functionality.
type View interface {
	// TODO: Add Send and Receive when mq_timedsend(2) and mq_timedreceive(2)
	// are implemented.

	// Flush checks if the calling process has attached a notification request
	// to this queue, if yes, then the request is removed, and another process
	// can attach a request.
	Flush(ctx context.Context)

	waiter.Waitable
}

// ReaderWriter provides a send and receive view into a queue.
type ReaderWriter struct {
	*Queue

	block bool
}

// Reader provides a send-only view into a queue.
type Reader struct {
	*Queue

	block bool
}

// Writer provides a receive-only view into a queue.
type Writer struct {
	*Queue

	block bool
}

// NewView creates a new view into a queue and returns it.
func NewView(q *Queue, rOnly, wOnly, readWrite, block bool) (View, error) {
	switch {
	case readWrite:
		return ReaderWriter{Queue: q, block: block}, nil
	case wOnly:
		return Writer{Queue: q, block: block}, nil
	case rOnly:
		return Reader{Queue: q, block: block}, nil
	default:
		// This case can't happen, due to O_RDONLY flag being 0 and O_WRONLY
		// being 1, so one of them must be true.
		return nil, linuxerr.EINVAL
	}
}

// Message holds a message exchanged through a Queue via mq_timedsend(2) and
// mq_timedreceive(2), and additional info relating to the message.
//
// +stateify savable
type Message struct {
	msgEntry

	// Text is the message's sent content.
	Text string

	// Size is the message's size in bytes.
	Size uint64

	// Priority is the message's priority.
	Priority uint32
}

// Subscriber represents a task registered for async notification from a Queue.
//
// +stateify savable
type Subscriber struct {
	// TODO: Add fields when mq_notify(2) is implemented.

	// pid is the PID of the registered task.
	pid int32
}

// Generate implements vfs.DynamicBytesSource.Generate. Queue is used as a
// DynamicBytesSource for mqfs's queueInode.
func (q *Queue) Generate(ctx context.Context, buf *bytes.Buffer) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	var (
		pid       int32
		method    int
		sigNumber int
	)
	if q.subscriber != nil {
		pid = q.subscriber.pid
		// TODO: add method and sigNumber when mq_notify(2) is implemented.
	}

	buf.WriteString(
		fmt.Sprintf("QSIZE:%-10d NOTIFY:%-5d SIGNO:%-5d NOTIFY_PID:%-6d\n",
			q.byteCount, method, sigNumber, pid),
	)
	return nil
}

// Flush implements View.Flush.
func (q *Queue) Flush(ctx context.Context) {
	q.mu.Lock()
	defer q.mu.Unlock()

	pid, ok := context.ThreadGroupIDFromContext(ctx)
	if ok {
		if q.subscriber != nil && pid == q.subscriber.pid {
			q.subscriber = nil
		}
	}
}

// Readiness implements Waitable.Readiness.
func (q *Queue) Readiness(mask waiter.EventMask) waiter.EventMask {
	q.mu.Lock()
	defer q.mu.Unlock()

	events := waiter.EventMask(0)
	if q.messageCount > 0 {
		events |= waiter.ReadableEvents
	}
	if q.messageCount < q.maxMessageCount {
		events |= waiter.WritableEvents
	}
	return events & mask
}

// EventRegister implements Waitable.EventRegister.
func (q *Queue) EventRegister(e *waiter.Entry, mask waiter.EventMask) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if mask&waiter.WritableEvents != 0 {
		q.senders.EventRegister(e, waiter.EventOut)
	}
	if mask&waiter.ReadableEvents != 0 {
		q.receivers.EventRegister(e, waiter.EventIn)
	}
}

// EventUnregister implements Waitable.EventUnregister.
func (q *Queue) EventUnregister(e *waiter.Entry) {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.senders.EventUnregister(e)
	q.receivers.EventUnregister(e)
}

// HasPermissions returns true if the given credentials meet the access
// permissions required by the queue.
func (q *Queue) HasPermissions(creds *auth.Credentials, req fs.PermMask) bool {
	p := q.perms.Other
	if q.owner.UID == creds.EffectiveKUID {
		p = q.perms.User
	} else if creds.InGroup(q.owner.GID) {
		p = q.perms.Group
	}
	return p.SupersetOf(req)
}
