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

package usage

import (
	"sync/atomic"
)

// IO contains I/O-related statistics.
//
// +stateify savable
type IO struct {
	// CharsRead is the number of bytes read by read syscalls.
	CharsRead uint64

	// CharsWritten is the number of bytes written by write syscalls.
	CharsWritten uint64

	// ReadSyscalls is the number of read syscalls.
	ReadSyscalls uint64

	// WriteSyscalls is the number of write syscalls.
	WriteSyscalls uint64

	// The following counter is only meaningful when Sentry has internal
	// pagecache.

	// BytesRead is the number of bytes actually read into pagecache.
	BytesRead uint64

	// BytesWritten is the number of bytes actually written from pagecache.
	BytesWritten uint64

	// BytesWriteCancelled is the number of bytes not written out due to
	// truncation.
	BytesWriteCancelled uint64
}

// AccountReadSyscall does the accounting for a read syscall.
func (i *IO) AccountReadSyscall(bytes int64) {
	atomic.AddUint64(&i.ReadSyscalls, 1)
	if bytes > 0 {
		atomic.AddUint64(&i.CharsRead, uint64(bytes))
	}
}

// AccountWriteSyscall does the accounting for a write syscall.
func (i *IO) AccountWriteSyscall(bytes int64) {
	atomic.AddUint64(&i.WriteSyscalls, 1)
	if bytes > 0 {
		atomic.AddUint64(&i.CharsWritten, uint64(bytes))
	}
}

// AccountReadIO does the accounting for a read IO into the file system.
func (i *IO) AccountReadIO(bytes int64) {
	if bytes > 0 {
		atomic.AddUint64(&i.BytesRead, uint64(bytes))
	}
}

// AccountWriteIO does the accounting for a write IO into the file system.
func (i *IO) AccountWriteIO(bytes int64) {
	if bytes > 0 {
		atomic.AddUint64(&i.BytesWritten, uint64(bytes))
	}
}

// Accumulate adds up io usages.
func (i *IO) Accumulate(io *IO) {
	atomic.AddUint64(&i.CharsRead, atomic.LoadUint64(&io.CharsRead))
	atomic.AddUint64(&i.CharsWritten, atomic.LoadUint64(&io.CharsWritten))
	atomic.AddUint64(&i.ReadSyscalls, atomic.LoadUint64(&io.ReadSyscalls))
	atomic.AddUint64(&i.WriteSyscalls, atomic.LoadUint64(&io.WriteSyscalls))
	atomic.AddUint64(&i.BytesRead, atomic.LoadUint64(&io.BytesRead))
	atomic.AddUint64(&i.BytesWritten, atomic.LoadUint64(&io.BytesWritten))
	atomic.AddUint64(&i.BytesWriteCancelled, atomic.LoadUint64(&io.BytesWriteCancelled))
}
