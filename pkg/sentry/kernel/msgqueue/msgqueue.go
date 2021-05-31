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

	// mType is an integer representing the type of the sent message.
	mType int64

	// mText is an untyped block of memory.
	mText []byte

	// mSize is the size of mText.
	mSize uint64
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

// Destroy implements ipc.Mechanism.Destroy. It's yet to be implemented.
func (q *Queue) Destroy() {
}
