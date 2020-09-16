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

import "encoding/binary"

// AIORingSize is sizeof(struct aio_ring).
const AIORingSize = 32

// I/O commands.
const (
	IOCB_CMD_PREAD  = 0
	IOCB_CMD_PWRITE = 1
	IOCB_CMD_FSYNC  = 2
	IOCB_CMD_FDSYNC = 3
	// 4 was the experimental IOCB_CMD_PREADX.
	IOCB_CMD_POLL    = 5
	IOCB_CMD_NOOP    = 6
	IOCB_CMD_PREADV  = 7
	IOCB_CMD_PWRITEV = 8
)

// I/O flags.
const (
	IOCB_FLAG_RESFD  = 1
	IOCB_FLAG_IOPRIO = 2
)

// IOCallback describes an I/O request.
//
// The priority field is currently ignored in the implementation below. Also
// note that the IOCB_FLAG_RESFD feature is not supported.
//
// +marshal
type IOCallback struct {
	Data uint64
	Key  uint32
	_    uint32

	OpCode  uint16
	ReqPrio int16
	FD      int32

	Buf    uint64
	Bytes  uint64
	Offset int64

	Reserved2 uint64
	Flags     uint32

	// eventfd to signal if IOCB_FLAG_RESFD is set in flags.
	ResFD int32
}

// IOEvent describes an I/O result.
//
// +marshal
// +stateify savable
type IOEvent struct {
	Data    uint64
	Obj     uint64
	Result  int64
	Result2 int64
}

// IOEventSize is the size of an ioEvent encoded.
var IOEventSize = binary.Size(IOEvent{})
