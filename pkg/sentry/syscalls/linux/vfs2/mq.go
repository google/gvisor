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
	"gvisor.dev/gvisor/pkg/sentry/arch"
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

	var attr linux.MqAttr
	var attrPtr *linux.MqAttr
	if attrAddr != 0 {
		if _, err := attr.CopyIn(t, attrAddr); err != nil {
			return 0, nil, err
		}
		attrPtr = &attr
	}

	opts := openOpts(name, rOnly, wOnly, readWrite, create, exclusive, block)

	r := t.IPCNamespace().PosixQueues()
	queue, err := r.FindOrCreate(t, opts, linux.FileMode(mode), attrPtr)
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
