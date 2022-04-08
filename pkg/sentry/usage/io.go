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

import "gvisor.dev/gvisor/pkg/atomicbitops"

// IO contains I/O-related statistics.
//
// +stateify savable
type IO struct {
	// CharsRead is the number of bytes read by read syscalls.
	CharsRead atomicbitops.Uint64

	// CharsWritten is the number of bytes written by write syscalls.
	CharsWritten atomicbitops.Uint64

	// ReadSyscalls is the number of read syscalls.
	ReadSyscalls atomicbitops.Uint64

	// WriteSyscalls is the number of write syscalls.
	WriteSyscalls atomicbitops.Uint64

	// The following counter is only meaningful when Sentry has internal
	// pagecache.

	// BytesRead is the number of bytes actually read into pagecache.
	BytesRead atomicbitops.Uint64

	// BytesWritten is the number of bytes actually written from pagecache.
	BytesWritten atomicbitops.Uint64

	// BytesWriteCancelled is the number of bytes not written out due to
	// truncation.
	BytesWriteCancelled atomicbitops.Uint64
}

// Clone turns other into a clone of i.
func (i *IO) Clone(other *IO) {
	other.CharsRead.Store(i.CharsRead.Load())
	other.CharsWritten.Store(i.CharsWritten.Load())
	other.ReadSyscalls.Store(i.ReadSyscalls.Load())
	other.WriteSyscalls.Store(i.WriteSyscalls.Load())
	other.BytesRead.Store(i.BytesRead.Load())
	other.BytesWritten.Store(i.BytesWritten.Load())
	other.BytesWriteCancelled.Store(i.BytesWriteCancelled.Load())
}

// AccountReadSyscall does the accounting for a read syscall.
func (i *IO) AccountReadSyscall(bytes int64) {
	i.ReadSyscalls.Add(1)
	if bytes > 0 {
		i.CharsRead.Add(uint64(bytes))
	}
}

// AccountWriteSyscall does the accounting for a write syscall.
func (i *IO) AccountWriteSyscall(bytes int64) {
	i.WriteSyscalls.Add(1)
	if bytes > 0 {
		i.CharsWritten.Add(uint64(bytes))
	}
}

// AccountReadIO does the accounting for a read IO into the file system.
func (i *IO) AccountReadIO(bytes int64) {
	if bytes > 0 {
		i.BytesRead.Add(uint64(bytes))
	}
}

// AccountWriteIO does the accounting for a write IO into the file system.
func (i *IO) AccountWriteIO(bytes int64) {
	if bytes > 0 {
		i.BytesWritten.Add(uint64(bytes))
	}
}

// Accumulate adds up io usages.
func (i *IO) Accumulate(io *IO) {
	i.CharsRead.Add(io.CharsRead.Load())
	i.CharsWritten.Add(io.CharsWritten.Load())
	i.ReadSyscalls.Add(io.ReadSyscalls.Load())
	i.WriteSyscalls.Add(io.WriteSyscalls.Load())
	i.BytesRead.Add(io.BytesRead.Load())
	i.BytesWritten.Add(io.BytesWritten.Load())
	i.BytesWriteCancelled.Add(io.BytesWriteCancelled.Load())
}
