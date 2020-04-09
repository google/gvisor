// Copyright 2019 The gVisor Authors.
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

const (
	// SFD_NONBLOCK is a signalfd(2) flag.
	SFD_NONBLOCK = 00004000

	// SFD_CLOEXEC is a signalfd(2) flag.
	SFD_CLOEXEC = 02000000
)

// SignalfdSiginfo is the siginfo encoding for signalfds.
type SignalfdSiginfo struct {
	Signo   uint32
	Errno   int32
	Code    int32
	PID     uint32
	UID     uint32
	FD      int32
	TID     uint32
	Band    uint32
	Overrun uint32
	TrapNo  uint32
	Status  int32
	Int     int32
	Ptr     uint64
	UTime   uint64
	STime   uint64
	Addr    uint64
	AddrLSB uint16
	_       [48]uint8
}
