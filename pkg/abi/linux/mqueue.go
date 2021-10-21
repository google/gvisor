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

package linux

// Default values for POSIX message queues. Source:
// include/linux/ipc_namespace.h
const (
	DFLT_QUEUESMAX       = 256
	MIN_MSGMAX           = 1
	DFLT_MSG        uint = 10
	DFLT_MSGMAX          = 10
	HARD_MSGMAX          = 65536
	MIN_MSGSIZEMAX       = 128
	DFLT_MSGSIZE    uint = 8192
	DFLT_MSGSIZEMAX      = 8192
	HARD_MSGSIZEMAX      = (16 * 1024 * 1024)
)

// Maximum values for a message queue. Source: include/uapi/linux/mqueue.h
const (
	MQ_PRIO_MAX  = 32768
	MQ_BYTES_MAX = 819200
)

// Codes used by mq_notify. Source: include/uapi/linux/mqueue.h
const (
	NOTIFY_NONE    = 0
	NOTIFY_WOKENUP = 1
	NOTIFY_REMOVED = 2

	NOTIFY_COOKIE_LEN = 32
)

// MqAttr is equivelant to struct mq_attr. Source: include/uapi/linux/mqueue.h
//
// +marshal
type MqAttr struct {
	MqFlags   int64    // Message queue flags.
	MqMaxmsg  int64    // Maximum number of messages.
	MqMsgsize int64    // Maximum message size.
	MqCurmsgs int64    // Number of messages currently queued.
	_         [4]int64 // Ignored for input, zeroed for output.
}
