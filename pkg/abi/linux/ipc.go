// Copyright 2018 The gVisor Authors.
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

// Control commands used with semctl, shmctl, and msgctl. Source:
// include/uapi/linux/ipc.h.
const (
	IPC_RMID = 0
	IPC_SET  = 1
	IPC_STAT = 2
	IPC_INFO = 3
)

// resource get request flags. Source: include/uapi/linux/ipc.h
const (
	IPC_CREAT  = 00001000
	IPC_EXCL   = 00002000
	IPC_NOWAIT = 00004000
)

const IPC_PRIVATE = 0

// In Linux, amd64 does not enable CONFIG_ARCH_WANT_IPC_PARSE_VERSION, so SysV
// IPC unconditionally uses the "new" 64-bit structures that are needed for
// features like 32-bit UIDs.

// IPCPerm is equivalent to struct ipc64_perm.
//
// +marshal
type IPCPerm struct {
	Key     uint32
	UID     uint32
	GID     uint32
	CUID    uint32
	CGID    uint32
	Mode    uint16
	_       uint16
	Seq     uint16
	_       uint16
	_       uint32
	unused1 uint64
	unused2 uint64
}
