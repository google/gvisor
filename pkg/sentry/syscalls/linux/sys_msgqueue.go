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
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/kernel/ipc"
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
