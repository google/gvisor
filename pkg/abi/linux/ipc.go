// Copyright 2018 Google Inc.
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

// Control commands used with semctl. Source: //include/uapi/linux/ipc.h.
const (
	IPC_RMID = 0
	IPC_SET  = 1
	IPC_STAT = 2
	IPC_INFO = 3
)

// resource get request flags. Source: //include/uapi/linux/ipc.h
const (
	IPC_CREAT  = 00001000
	IPC_EXCL   = 00002000
	IPC_NOWAIT = 00004000
)

const IPC_PRIVATE = 0

// IPCPerm is equivalent to struct ipc_perm.
type IPCPerm struct {
	Key       uint32
	UID       uint32
	GID       uint32
	CUID      uint32
	CGID      uint32
	Mode      uint16
	pad1      uint16
	Seq       uint16
	pad2      uint16
	reserved1 uint32
	reserved2 uint32
}
