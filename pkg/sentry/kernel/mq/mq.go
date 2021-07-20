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
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	maxPriority = linux.MQ_PRIO_MAX - 1 // Highest possible message priority.
)

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
	subscriber Subscriber

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
}
