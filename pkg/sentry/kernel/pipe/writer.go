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

// Writer satisfies the fs.FileOperations interface for write-only pipes.
// Writer should be used with !fs.FileFlags.Read to reject reads.
//
// +stateify savable
type Writer struct {
	ReaderWriter
}

// Release implements fs.FileOperations.Release.
//
// This overrides ReaderWriter.Release.
func (w *Writer) Release(context.Context) {
	w.Pipe.wClose()

	// Wake up readers.
	w.Pipe.queue.Notify(waiter.EventHUp)
}

// Readiness returns the ready events in the underlying pipe.
func (w *Writer) Readiness(mask waiter.EventMask) waiter.EventMask {
	return w.Pipe.wReadiness() & mask
}
