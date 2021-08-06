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

// Package msgqueue implements System V message queues.
package msgqueue

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/kernel/ipc"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	// System-wide limit for maximum number of queues.
	maxQueues = linux.MSGMNI

	// Maximum size of a queue in bytes.
	maxQueueBytes = linux.MSGMNB

	// Maximum size of a message in bytes.
	maxMessageBytes = linux.MSGMAX
)

// Registry contains a set of message queues that can be referenced using keys
// or IDs.
//
// +stateify savable
type Registry struct {
	// mu protects all the fields below.
	mu sync.Mutex `state:"nosave"`

	// reg defines basic fields and operations needed for all SysV registries.
	reg *ipc.Registry
}

// NewRegistry returns a new Registry ready to be used.
func NewRegistry(userNS *auth.UserNamespace) *Registry {
	return &Registry{
		reg: ipc.NewRegistry(userNS),
	}
}

// Queue represents a SysV message queue, described by sysvipc(7).
//
// +stateify savable
type Queue struct {
	// registry is the registry owning this queue. Immutable.
	registry *Registry

	// mu protects all the fields below.
	mu sync.Mutex `state:"nosave"`

	// dead is set to true when a queue is removed from the registry and should
	// not be used. Operations on the queue should check dead, and return
	// EIDRM if set to true.
	dead bool

	// obj defines basic fields that should be included in all SysV IPC objects.
	obj *ipc.Object

	// senders holds a queue of blocked message senders. Senders are notified
	// when enough space is available in the queue to insert their message.
	senders waiter.Queue

	// receivers holds a queue of blocked receivers. Receivers are notified
	// when a new message is inserted into the queue and can be received.
	receivers waiter.Queue

	// messages is a list of sent messages.
	messages msgList

	// sendTime is the last time a msgsnd was perfomed.
	sendTime ktime.Time

	// receiveTime is the last time a msgrcv was performed.
	receiveTime ktime.Time

	// changeTime is the last time the queue was modified using msgctl.
	changeTime ktime.Time

	// byteCount is the current number of message bytes in the queue.
	byteCount uint64

	// messageCount is the current number of messages in the queue.
	messageCount uint64

	// maxBytes is the maximum allowed number of bytes in the queue, and is also
	// used as a limit for the number of total possible messages.
	maxBytes uint64

	// sendPID is the PID of the process that performed the last msgsnd.
	sendPID int32

	// receivePID is the PID of the process that performed the last msgrcv.
	receivePID int32
}

// Message represents a message exchanged through a Queue via msgsnd(2) and
// msgrcv(2).
//
// +stateify savable
type Message struct {
	msgEntry

	// Type is an integer representing the type of the sent message.
	Type int64

	// Text is an untyped block of memory.
	Text []byte

	// Size is the size of Text.
	Size uint64
}

// Blocker is used for blocking Queue.Send, and Queue.Receive calls that serves
// as an abstracted version of kernel.Task. kernel.Task is not directly used to
// prevent circular dependencies.
type Blocker interface {
	Block(C <-chan struct{}) error
}

// FindOrCreate creates a new message queue or returns an existing one. See
// msgget(2).
func (r *Registry) FindOrCreate(ctx context.Context, key ipc.Key, mode linux.FileMode, private, create, exclusive bool) (*Queue, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !private {
		queue, err := r.reg.Find(ctx, key, mode, create, exclusive)
		if err != nil {
			return nil, err
		}

		if queue != nil {
			return queue.(*Queue), nil
		}
	}

	// Check system-wide limits.
	if r.reg.ObjectCount() >= maxQueues {
		return nil, linuxerr.ENOSPC
	}

	return r.newQueueLocked(ctx, key, fs.FileOwnerFromContext(ctx), fs.FilePermsFromMode(mode))
}

// newQueueLocked creates a new queue using the given fields. An error is
// returned if there're no more available identifiers.
//
// Precondition: r.mu must be held.
func (r *Registry) newQueueLocked(ctx context.Context, key ipc.Key, creator fs.FileOwner, perms fs.FilePermissions) (*Queue, error) {
	q := &Queue{
		registry:    r,
		obj:         ipc.NewObject(r.reg.UserNS, key, creator, creator, perms),
		sendTime:    ktime.ZeroTime,
		receiveTime: ktime.ZeroTime,
		changeTime:  ktime.NowFromContext(ctx),
		maxBytes:    maxQueueBytes,
	}

	err := r.reg.Register(q)
	if err != nil {
		return nil, err
	}
	return q, nil
}

// Remove removes the queue with specified ID. All waiters (readers and
// writers) and writers will be awakened and fail. Remove will return an error
// if the ID is invalid, or the the user doesn't have privileges.
func (r *Registry) Remove(id ipc.ID, creds *auth.Credentials) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.reg.Remove(id, creds)
	return nil
}

// FindByID returns the queue with the specified ID and an error if the ID
// doesn't exist.
func (r *Registry) FindByID(id ipc.ID) (*Queue, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	mech := r.reg.FindByID(id)
	if mech == nil {
		return nil, linuxerr.EINVAL
	}
	return mech.(*Queue), nil
}

// Send appends a message to the message queue, and returns an error if sending
// fails. See msgsnd(2).
func (q *Queue) Send(ctx context.Context, m Message, b Blocker, wait bool, pid int32) error {
	// Try to perform a non-blocking send using queue.append. If EWOULDBLOCK
	// is returned, start the blocking procedure. Otherwise, return normally.
	creds := auth.CredentialsFromContext(ctx)

	// Fast path: first attempt a non-blocking push.
	if err := q.push(ctx, m, creds, pid); err != linuxerr.EWOULDBLOCK {
		return err
	}

	if !wait {
		return linuxerr.EAGAIN
	}

	// Slow path: at this point, the queue was found to be full, and we were
	// asked to block.

	e, ch := waiter.NewChannelEntry(nil)
	q.senders.EventRegister(&e, waiter.EventOut)
	defer q.senders.EventUnregister(&e)

	// Note: we need to check again before blocking the first time since space
	// may have become available.
	for {
		if err := q.push(ctx, m, creds, pid); err != linuxerr.EWOULDBLOCK {
			return err
		}
		if err := b.Block(ch); err != nil {
			return err
		}
	}
}

// push appends a message to the queue's message list and notifies waiting
// receivers that a message has been inserted. It returns an error if adding
// the message would cause the queue to exceed its maximum capacity, which can
// be used as a signal to block the task. Other errors should be returned as is.
func (q *Queue) push(ctx context.Context, m Message, creds *auth.Credentials, pid int32) error {
	if m.Type <= 0 {
		return linuxerr.EINVAL
	}

	q.mu.Lock()
	defer q.mu.Unlock()

	if !q.obj.CheckPermissions(creds, fs.PermMask{Write: true}) {
		// The calling process does not have write permission on the message
		// queue, and does not have the CAP_IPC_OWNER capability in the user
		// namespace that governs its IPC namespace.
		return linuxerr.EACCES
	}

	// Queue was removed while the process was waiting.
	if q.dead {
		return linuxerr.EIDRM
	}

	// Check if sufficient space is available (the queue isn't full.) From
	// the man pages:
	//
	// "A message queue is considered to be full if either of the following
	// conditions is true:
	//
	//  • Adding a new message to the queue would cause the total number
	//    of bytes in the queue to exceed the queue's maximum size (the
	//    msg_qbytes field).
	//
	//  • Adding another message to the queue would cause the total
	//    number of messages in the queue to exceed the queue's maximum
	//    size (the msg_qbytes field).  This check is necessary to
	//    prevent an unlimited number of zero-length messages being
	//    placed on the queue.  Although such messages contain no data,
	//    they nevertheless consume (locked) kernel memory."
	//
	// The msg_qbytes field in our implementation is q.maxBytes.
	if m.Size+q.byteCount > q.maxBytes || q.messageCount+1 > q.maxBytes {
		return linuxerr.EWOULDBLOCK
	}

	// Copy the message into the queue.
	q.messages.PushBack(&m)

	q.byteCount += m.Size
	q.messageCount++
	q.sendPID = pid
	q.sendTime = ktime.NowFromContext(ctx)

	// Notify receivers about the new message.
	q.receivers.Notify(waiter.EventIn)

	return nil
}

// Receive removes a message from the queue and returns it. See msgrcv(2).
func (q *Queue) Receive(ctx context.Context, b Blocker, mType int64, maxSize int64, wait, truncate, except bool, pid int32) (*Message, error) {
	if maxSize < 0 || maxSize > maxMessageBytes {
		return nil, linuxerr.EINVAL
	}
	max := uint64(maxSize)
	creds := auth.CredentialsFromContext(ctx)

	// Fast path: first attempt a non-blocking pop.
	if msg, err := q.pop(ctx, creds, mType, max, truncate, except, pid); err != linuxerr.EWOULDBLOCK {
		return msg, err
	}

	if !wait {
		return nil, linuxerr.ENOMSG
	}

	// Slow path: at this point, the queue was found to be empty, and we were
	// asked to block.

	e, ch := waiter.NewChannelEntry(nil)
	q.receivers.EventRegister(&e, waiter.EventIn)
	defer q.receivers.EventUnregister(&e)

	// Note: we need to check again before blocking the first time since a
	// message may have become available.
	for {
		if msg, err := q.pop(ctx, creds, mType, max, truncate, except, pid); err != linuxerr.EWOULDBLOCK {
			return msg, err
		}
		if err := b.Block(ch); err != nil {
			return nil, err
		}
	}
}

// pop pops the first message from the queue that matches the given type. It
// returns an error for all the cases specified in msgrcv(2). If the queue is
// empty or no message of the specified type is available, a EWOULDBLOCK error
// is returned, which can then be used as a signal to block the process or fail.
func (q *Queue) pop(ctx context.Context, creds *auth.Credentials, mType int64, maxSize uint64, truncate, except bool, pid int32) (*Message, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if !q.obj.CheckPermissions(creds, fs.PermMask{Read: true}) {
		// The calling process does not have read permission on the message
		// queue, and does not have the CAP_IPC_OWNER capability in the user
		// namespace that governs its IPC namespace.
		return nil, linuxerr.EACCES
	}

	// Queue was removed while the process was waiting.
	if q.dead {
		return nil, linuxerr.EIDRM
	}

	if q.messages.Empty() {
		return nil, linuxerr.EWOULDBLOCK
	}

	// Get a message from the queue.
	var msg *Message
	switch {
	case mType == 0:
		msg = q.messages.Front()
	case mType > 0:
		msg = q.msgOfType(mType, except)
	case mType < 0:
		msg = q.msgOfTypeLessThan(-1 * mType)
	}

	// If no message exists, return a blocking singal.
	if msg == nil {
		return nil, linuxerr.EWOULDBLOCK
	}

	// Check message's size is acceptable.
	if maxSize < msg.Size {
		if !truncate {
			return nil, linuxerr.E2BIG
		}
		msg.Size = maxSize
		msg.Text = msg.Text[:maxSize+1]
	}

	q.messages.Remove(msg)

	q.byteCount -= msg.Size
	q.messageCount--
	q.receivePID = pid
	q.receiveTime = ktime.NowFromContext(ctx)

	// Notify senders about available space.
	q.senders.Notify(waiter.EventOut)

	return msg, nil
}

// Copy copies a message from the queue without deleting it. If no message
// exists, an error is returned. See msgrcv(MSG_COPY).
func (q *Queue) Copy(mType int64) (*Message, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if mType < 0 || q.messages.Empty() {
		return nil, linuxerr.ENOMSG
	}

	msg := q.msgAtIndex(mType)
	if msg == nil {
		return nil, linuxerr.ENOMSG
	}
	return msg, nil
}

// msgOfType returns the first message with the specified type, nil if no
// message is found. If except is true, the first message of a type not equal
// to mType will be returned.
//
// Precondition: caller must hold q.mu.
func (q *Queue) msgOfType(mType int64, except bool) *Message {
	if except {
		for msg := q.messages.Front(); msg != nil; msg = msg.Next() {
			if msg.Type != mType {
				return msg
			}
		}
		return nil
	}

	for msg := q.messages.Front(); msg != nil; msg = msg.Next() {
		if msg.Type == mType {
			return msg
		}
	}
	return nil
}

// msgOfTypeLessThan return the the first message with the lowest type less
// than or equal to mType, nil if no such message exists.
//
// Precondition: caller must hold q.mu.
func (q *Queue) msgOfTypeLessThan(mType int64) (m *Message) {
	min := mType
	for msg := q.messages.Front(); msg != nil; msg = msg.Next() {
		if msg.Type <= mType && msg.Type < min {
			m = msg
			min = msg.Type
		}
	}
	return m
}

// msgAtIndex returns a pointer to a message at given index, nil if non exits.
//
// Precondition: caller must hold q.mu.
func (q *Queue) msgAtIndex(mType int64) *Message {
	msg := q.messages.Front()
	for ; mType != 0 && msg != nil; mType-- {
		msg = msg.Next()
	}
	return msg
}

// Lock implements ipc.Mechanism.Lock.
func (q *Queue) Lock() {
	q.mu.Lock()
}

// Unlock implements ipc.mechanism.Unlock.
//
// +checklocksignore
func (q *Queue) Unlock() {
	q.mu.Unlock()
}

// Object implements ipc.Mechanism.Object.
func (q *Queue) Object() *ipc.Object {
	return q.obj
}

// Destroy implements ipc.Mechanism.Destroy.
func (q *Queue) Destroy() {
	q.dead = true

	// Notify waiters. Senders and receivers will try to run, and return an
	// error (EIDRM). Waiters should remove themselves from the queue after
	// waking up.
	q.senders.Notify(waiter.EventOut)
	q.receivers.Notify(waiter.EventIn)
}

// ID returns queue's ID.
func (q *Queue) ID() ipc.ID {
	return q.obj.ID
}
