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

package vfs2

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/mqfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/mq"
)

// MqOpen implements mq_open(2).
func MqOpen(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	nameAddr := args[0].Pointer()
	flag := args[1].Int()
	mode := args[2].ModeT()
	attrAddr := args[3].Pointer()

	name, err := t.CopyInString(nameAddr, mq.MaxName)
	if err != nil {
		return 0, nil, err
	}

	rOnly := flag&linux.O_RDONLY == linux.O_RDONLY
	wOnly := flag&linux.O_WRONLY == linux.O_WRONLY
	readWrite := flag&linux.O_RDWR == linux.O_RDWR

	create := flag&linux.O_CREAT == linux.O_CREAT
	exclusive := flag&linux.O_EXCL == linux.O_EXCL
	block := flag&linux.O_NONBLOCK != linux.O_NONBLOCK

	attr, err := attributes(t, attrAddr)
	if err != nil {
		return 0, nil, err
	}

	opts := openOpts(name, rOnly, wOnly, readWrite, create, exclusive, block)

	r := t.IPCNamespace().PosixQueues()
	queue, err := r.FindOrCreate(t, opts, linux.FileMode(mode), attr)
	if err != nil {
		return 0, nil, err
	}

	fd, err := t.NewFDFromVFS2(0, queue, kernel.FDFlags{
		CloseOnExec: flag&linux.O_CLOEXEC != 0,
	})
	if err != nil {
		return 0, nil, err
	}
	return uintptr(fd), nil, nil
}

// MqUnlink implements mq_unlink(2).
func MqUnlink(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	nameAddr := args[0].Pointer()
	name, err := t.CopyInString(nameAddr, mq.MaxName)
	if err != nil {
		return 0, nil, err
	}
	return 0, nil, t.IPCNamespace().PosixQueues().Remove(t, name)
}

// MqTimedSend implements mq_timedsend(2).
func MqTimedSend(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	msgAddr := args[1].Pointer()
	size := args[2].SizeT()
	priority := args[3].Uint()
	timespecAddr := args[4].Pointer()

	msgStr, err := t.CopyInString(msgAddr, int(size)+1)
	if err != nil {
		return 0, nil, linuxerr.EINVAL
	}
	msg := mq.Message{
		Text:     msgStr,
		Size:     uint64(size),
		Priority: priority,
	}

	timeout, err := copyTimespecInToDuration(t, timespecAddr)
	if err != nil {
		return 0, nil, err
	}

	file := t.GetFileVFS2(fd)
	if file == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer file.DecRef(t)

	qFD, ok := file.Impl().(*mqfs.QueueFD)
	if !ok {
		return 0, nil, linuxerr.EBADF
	}

	q := qFD.Queue()
	if uint64(size) > q.Queue().MaxMsgSize() {
		return 0, nil, linuxerr.EMSGSIZE
	}
	return 0, nil, q.Send(t, msg, t, timeout)
}

// MqTimedReceive implements mq_timedreceive(2).
func MqTimedReceive(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	msgAddr := args[1].Pointer()
	size := args[2].SizeT()
	priorityAddr := args[3].Pointer()
	timespecAddr := args[4].Pointer()

	timeout, err := copyTimespecInToDuration(t, timespecAddr)
	if err != nil {
		return 0, nil, err
	}

	file := t.GetFileVFS2(fd)
	if file == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer file.DecRef(t)

	qFD, ok := file.Impl().(*mqfs.QueueFD)
	if !ok {
		return 0, nil, linuxerr.EBADF
	}

	q := qFD.Queue()
	if uint64(size) < q.Queue().MaxMsgSize() {
		return 0, nil, linuxerr.EMSGSIZE
	}

	msg, err := q.Receive(t, t, timeout)
	if err != nil {
		return 0, nil, err
	}

	n, err := primitive.CopyStringOut(t, msgAddr, msg.Text)
	if err != nil {
		return 0, nil, err
	}

	if priorityAddr != 0 {
		_, err := primitive.CopyUint32Out(t, priorityAddr, msg.Priority)
		if err != nil {
			return 0, nil, err
		}
	}
	return uintptr(n), nil, nil
}

// MqGetSetAttr implements mq_getsetattr(2).
func MqGetSetAttr(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	newAddr := args[1].Pointer()
	oldAddr := args[2].Pointer()

	newAttr, err := attributes(t, newAddr)
	if err != nil {
		return 0, nil, err
	}

	if newAttr != nil {
		if newAttr.MqFlags&(^linux.O_NONBLOCK) != 0 {
			return 0, nil, linuxerr.EINVAL
		}
	}

	file := t.GetFileVFS2(fd)
	if file == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer file.DecRef(t)

	qFD, ok := file.Impl().(*mqfs.QueueFD)
	if !ok {
		return 0, nil, linuxerr.EBADF
	}

	if oldAddr != 0 {
		oldAttr := qFD.Queue().Attr()
		if _, err := oldAttr.CopyOut(t, oldAddr); err != nil {
			return 0, nil, err
		}
	}

	if newAttr != nil {
		qFD.Queue().Set((newAttr.MqFlags & linux.O_NONBLOCK) != linux.O_NONBLOCK)
	}
	return 0, nil, nil
}

// MqNotify implements mq_notify(2).
func MqNotify(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	eventAddr := args[1].Pointer()

	file := t.GetFileVFS2(fd)
	if file == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer file.DecRef(t)

	qFD, ok := file.Impl().(*mqfs.QueueFD)
	if !ok {
		return 0, nil, linuxerr.EBADF
	}

	if eventAddr != 0 {
		var event linux.Sigevent
		if _, err := event.CopyIn(t, eventAddr); err != nil {
			return 0, nil, err
		}

		return 0, nil, qFD.Queue().Register(t, &event, int32(t.ThreadGroup().ID()))
	}

	qFD.Queue().Unregister(int32(t.ThreadGroup().ID()))
	return 0, nil, nil
}

func openOpts(name string, rOnly, wOnly, readWrite, create, exclusive, block bool) mq.OpenOpts {
	var access mq.AccessType
	switch {
	case readWrite:
		access = mq.ReadWrite
	case wOnly:
		access = mq.WriteOnly
	case rOnly:
		access = mq.ReadOnly
	}

	return mq.OpenOpts{
		Name:      name,
		Access:    access,
		Create:    create,
		Exclusive: exclusive,
		Block:     block,
	}
}

// attributes returns a linux.MqAttr read from attrAddr if the address is not
// null, otherwise nil is returned. An error is returned if copying fails.
func attributes(t *kernel.Task, attrAddr hostarch.Addr) (*linux.MqAttr, error) {
	if attrAddr != 0 {
		var attr linux.MqAttr
		if _, err := attr.CopyIn(t, attrAddr); err != nil {
			return nil, err
		}
		return &attr, nil
	}
	return nil, nil
}
