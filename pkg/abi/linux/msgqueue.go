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

import (
	"gvisor.dev/gvisor/pkg/marshal/primitive"
)

// Linux-specific control commands. Source: include/uapi/linux/msg.h
const (
	MSG_STAT     = 11
	MSG_INFO     = 12
	MSG_STAT_ANY = 13
)

// msgrcv(2) options. Source: include/uapi/linux/msg.h
const (
	MSG_NOERROR = 010000 // No error if message is too big.
	MSG_EXCEPT  = 020000 // Receive any message except of specified type.
	MSG_COPY    = 040000 // Copy (not remove) all queue messages.
)

// System-wide limits for message queues. Source: include/uapi/linux/msg.h
const (
	MSGMNI = 32000 // Maximum number of message queue identifiers.
	MSGMAX = 8192  // Maximum size of message (bytes).
	MSGMNB = 16384 // Default max size of a message queue.
)

// System-wide limits. Unused. Source: include/uapi/linux/msg.h
const (
	MSGPOOL = (MSGMNI * MSGMNB / 1024)
	MSGTQL  = MSGMNB
	MSGMAP  = MSGMNB
	MSGSSZ  = 16

	// MSGSEG is simplified due to the inexistance of a ternary operator.
	MSGSEG = (MSGPOOL * 1024) / MSGSSZ
)

// MsqidDS is equivelant to struct msqid64_ds. Source:
// include/uapi/asm-generic/shmbuf.h
//
// +marshal
type MsqidDS struct {
	MsgPerm   IPCPerm // IPC permissions.
	MsgStime  TimeT   // Last msgsnd time.
	MsgRtime  TimeT   // Last msgrcv time.
	MsgCtime  TimeT   // Last change time.
	MsgCbytes uint64  // Current number of bytes on the queue.
	MsgQnum   uint64  // Number of messages in the queue.
	MsgQbytes uint64  // Max number of bytes in the queue.
	MsgLspid  int32   // PID of last msgsnd.
	MsgLrpid  int32   // PID of last msgrcv.
	unused4   uint64
	unused5   uint64
}

// MsgBuf is equivelant to struct msgbuf. Source: include/uapi/linux/msg.h
//
// +marshal dynamic
type MsgBuf struct {
	Type primitive.Int64
	Text primitive.ByteSlice
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (b *MsgBuf) SizeBytes() int {
	return b.Type.SizeBytes() + b.Text.SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (b *MsgBuf) MarshalBytes(dst []byte) {
	b.Type.MarshalUnsafe(dst)
	b.Text.MarshalBytes(dst[b.Type.SizeBytes():])
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (b *MsgBuf) UnmarshalBytes(src []byte) {
	b.Type.UnmarshalUnsafe(src)
	b.Text.UnmarshalBytes(src[b.Type.SizeBytes():])
}

// MsgInfo is equivelant to struct msginfo. Source: include/uapi/linux/msg.h
//
// +marshal
type MsgInfo struct {
	MsgPool int32
	MsgMap  int32
	MsgMax  int32
	MsgMnb  int32
	MsgMni  int32
	MsgSsz  int32
	MsgTql  int32
	MsgSeg  uint16 `marshal:"unaligned"`
}
