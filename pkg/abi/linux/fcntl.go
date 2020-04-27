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

// Commands from linux/fcntl.h.
const (
	F_DUPFD         = 0
	F_GETFD         = 1
	F_SETFD         = 2
	F_GETFL         = 3
	F_SETFL         = 4
	F_SETLK         = 6
	F_SETLKW        = 7
	F_SETOWN        = 8
	F_GETOWN        = 9
	F_SETOWN_EX     = 15
	F_GETOWN_EX     = 16
	F_DUPFD_CLOEXEC = 1024 + 6
	F_SETPIPE_SZ    = 1024 + 7
	F_GETPIPE_SZ    = 1024 + 8
)

// Commands for F_SETLK.
const (
	F_RDLCK = 0
	F_WRLCK = 1
	F_UNLCK = 2
)

// Flags for fcntl.
const (
	FD_CLOEXEC = 00000001
)

// Flock is the lock structure for F_SETLK.
type Flock struct {
	Type   int16
	Whence int16
	_      [4]byte
	Start  int64
	Len    int64
	Pid    int32
	_      [4]byte
}

// Flags for F_SETOWN_EX and F_GETOWN_EX.
const (
	F_OWNER_TID  = 0
	F_OWNER_PID  = 1
	F_OWNER_PGRP = 2
)

// FOwnerEx is the owner structure for F_SETOWN_EX and F_GETOWN_EX.
type FOwnerEx struct {
	Type int32
	PID  int32
}
