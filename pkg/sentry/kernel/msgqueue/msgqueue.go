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
	"sync"

	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/kernel/ipc"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
	"gvisor.dev/gvisor/pkg/waiter"
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

// NewRegistry returns a new Registry ready to be used.
func NewRegistry(userNS *auth.UserNamespace) *Registry {
	return &Registry{
		reg: ipc.NewRegistry(userNS),
	}
}
