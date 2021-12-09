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

package pipe

import (
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/waiter"
)

// Reader satisfies the fs.FileOperations interface for read-only pipes.
// Reader should be used with !fs.FileFlags.Write to reject writes.
//
// +stateify savable
type Reader struct {
	ReaderWriter
}

// Release implements fs.FileOperations.Release.
//
// This overrides ReaderWriter.Release.
func (r *Reader) Release(context.Context) {
	r.Pipe.rClose()

	// Wake up writers.
	r.Pipe.queue.Notify(waiter.EventOut)
}

// Readiness returns the ready events in the underlying pipe.
func (r *Reader) Readiness(mask waiter.EventMask) waiter.EventMask {
	return r.Pipe.rReadiness() & mask
}
