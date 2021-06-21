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
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/kernel/ipc"
	"gvisor.dev/gvisor/pkg/sentry/kernel/msgqueue"
)

// Msgget implements msgget(2).
func Msgget(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	key := ipc.Key(args[0].Int())
	flag := args[1].Int()

	private := key == linux.IPC_PRIVATE
	create := flag&linux.IPC_CREAT == linux.IPC_CREAT
	exclusive := flag&linux.IPC_EXCL == linux.IPC_EXCL
	mode := linux.FileMode(flag & 0777)

	r := t.IPCNamespace().MsgqueueRegistry()
	queue, err := r.FindOrCreate(t, key, mode, private, create, exclusive)
	if err != nil {
		return 0, nil, err
	}
	return uintptr(queue.ID()), nil, nil
}

// Msgsnd implements msgsnd(2).
func Msgsnd(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	id := ipc.ID(args[0].Int())
	msgAddr := args[1].Pointer()
	size := args[2].Int64()
	flag := args[3].Int()

	if size < 0 || size > linux.MSGMAX {
		return 0, nil, linuxerr.EINVAL
	}

	wait := flag&linux.IPC_NOWAIT != linux.IPC_NOWAIT
	pid := int32(t.ThreadGroup().ID())

	buf := linux.MsgBuf{
		Text: make([]byte, size),
	}
	if _, err := buf.CopyIn(t, msgAddr); err != nil {
		return 0, nil, err
	}

	queue, err := t.IPCNamespace().MsgqueueRegistry().FindByID(id)
	if err != nil {
		return 0, nil, err
	}

	msg := msgqueue.Message{
		Type: int64(buf.Type),
		Text: buf.Text,
		Size: uint64(size),
	}
	return 0, nil, queue.Send(t, msg, t, wait, pid)
}

// Msgrcv implements msgrcv(2).
func Msgrcv(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	id := ipc.ID(args[0].Int())
	msgAddr := args[1].Pointer()
	size := args[2].Int64()
	mType := args[3].Int64()
	flag := args[4].Int()

	wait := flag&linux.IPC_NOWAIT != linux.IPC_NOWAIT
	except := flag&linux.MSG_EXCEPT == linux.MSG_EXCEPT
	truncate := flag&linux.MSG_NOERROR == linux.MSG_NOERROR

	msgCopy := flag&linux.MSG_COPY == linux.MSG_COPY

	msg, err := receive(t, id, mType, size, msgCopy, wait, truncate, except)
	if err != nil {
		return 0, nil, err
	}

	buf := linux.MsgBuf{
		Type: primitive.Int64(msg.Type),
		Text: msg.Text,
	}
	if _, err := buf.CopyOut(t, msgAddr); err != nil {
		return 0, nil, err
	}
	return uintptr(msg.Size), nil, nil
}

// receive returns a message from the queue with the given ID. If msgCopy is
// true, a message is copied from the queue without being removed. Otherwise,
// a message is removed from the queue and returned.
func receive(t *kernel.Task, id ipc.ID, mType int64, maxSize int64, msgCopy, wait, truncate, except bool) (*msgqueue.Message, error) {
	pid := int32(t.ThreadGroup().ID())

	queue, err := t.IPCNamespace().MsgqueueRegistry().FindByID(id)
	if err != nil {
		return nil, err
	}

	if msgCopy {
		return queue.Copy()
	}
	return queue.Receive(t, t, mType, maxSize, wait, truncate, except, pid)
}

// Msgctl implements msgctl(2).
func Msgctl(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	id := ipc.ID(args[0].Int())
	cmd := args[1].Int()

	creds := auth.CredentialsFromContext(t)

	switch cmd {
	case linux.IPC_RMID:
		return 0, nil, t.IPCNamespace().MsgqueueRegistry().Remove(id, creds)
	default:
		return 0, nil, linuxerr.EINVAL
	}
}
