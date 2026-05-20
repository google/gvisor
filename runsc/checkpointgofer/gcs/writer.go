// Copyright 2025 The gVisor Authors.
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

package gcs

import (
	"context"
	"fmt"

	"cloud.google.com/go/storage"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/state/stateio"
	"gvisor.dev/gvisor/pkg/sync"
)

// Writer implements stateio.AsyncWriter for a GCS object.
type Writer struct {
	stateio.NoRegisterClientFD

	maxWriteBytes uint64
	maxRanges     int
	obj           *storage.ObjectHandle
	writer        *storage.Writer
	subs          chan writeSubmission
	cmps          chan stateio.Completion
	cancel        context.CancelCauseFunc
	worker        sync.WaitGroup
}

type writeSubmission struct {
	id  int
	src stateio.LocalClientRanges
}

// NewWriter returns a Writer that writes to the given GCS object.
func NewWriter(ctx context.Context, obj *storage.ObjectHandle, maxWriteBytes uint64, maxRanges, maxParallel int) *Writer {
	ctx, cancel := context.WithCancelCause(ctx)
	w := &Writer{
		maxWriteBytes: maxWriteBytes,
		maxRanges:     maxRanges,
		obj:           obj,
		writer:        obj.NewWriter(ctx),
		subs:          make(chan writeSubmission, maxParallel),
		cmps:          make(chan stateio.Completion, maxParallel),
		cancel:        cancel,
	}
	w.writer.ChunkSize = int(w.maxWriteBytes)
	// Set Content-Type explicitly to avoid wasting time on Content-Type
	// autodetection.
	w.writer.ContentType = contentType
	w.worker.Add(1)
	go w.workerMain(ctx)
	return w
}

// Close implements stateio.AsyncWriter.Close.
func (w *Writer) Close() error {
	w.cancel(fmt.Errorf("context canceled by Writer.Close"))
	w.worker.Wait()
	if w.writer != nil {
		// We don't need to convert this to an errno for two reasons:
		//
		// - Finalize was never called, so the error returned by
		// w.writer.Close() is ultimately irrelevant.
		//
		// - stateipc implements stateio.AsyncReader/Writer.Close() via URPC;
		// URPC preserves error strings, but loses error types.
		return w.writer.Close()
	}
	// The error from w.writer.Close() was already returned by w.Finalize(); we
	// don't need to return it again.
	return nil
}

// MaxWriteBytes implements stateio.AsyncWriter.MaxWriteBytes.
func (w *Writer) MaxWriteBytes() uint64 {
	return w.maxWriteBytes
}

// MaxRanges implements stateio.AsyncWriter.MaxRanges.
func (w *Writer) MaxRanges() int {
	return w.maxRanges
}

// MaxParallel implements stateio.AsyncWriter.MaxParallel.
func (w *Writer) MaxParallel() int {
	return cap(w.subs)
}

// AddWrite implements stateio.AsyncWriter.AddWrite.
func (w *Writer) AddWrite(id int, _ stateio.SourceFile, _ memmap.FileRange, srcMap []byte) {
	w.subs <- writeSubmission{
		id:  id,
		src: stateio.LocalClientMapping(srcMap),
	}
}

// AddWritev implements stateio.AsyncWriter.AddWritev.
func (w *Writer) AddWritev(id int, total uint64, _ stateio.SourceFile, _ []memmap.FileRange, srcMaps []unix.Iovec) {
	w.subs <- writeSubmission{
		id:  id,
		src: stateio.LocalClientMappings(srcMaps),
	}
}

// Wait implements stateio.AsyncWriter.Wait.
func (w *Writer) Wait(cs []stateio.Completion, minCompletions int) ([]stateio.Completion, error) {
	return stateio.CompletionChanWait(w.cmps, cs, minCompletions)
}

// Reserve implements stateio.AsyncWriter.Reserve.
func (w *Writer) Reserve(n uint64) {
	// no-op
}

// Finalize implements stateio.AsyncWriter.Finalize.
func (w *Writer) Finalize() error {
	sw := w.writer
	w.writer = nil
	if err := sw.Close(); err != nil {
		if code, ok := httpCodeFromError(err); ok && isPermissionDeniedCode(code) {
			log.Infof("gcs.Writer returning EACCES for close error: %v", err)
			return unix.EACCES
		}
		return err
	}
	return nil
}

func (w *Writer) workerMain(ctx context.Context) {
	defer w.worker.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case sub := <-w.subs:
			var done uint64
			var doneErr error
			for _, src := range sub.src.Mappings {
				n, err := w.writer.Write(src)
				done += uint64(n)
				if err != nil {
					doneErr = err
					break
				}
			}
			if doneErr != nil {
				if code, ok := httpCodeFromError(doneErr); ok && isPermissionDeniedCode(code) {
					log.Infof("gcs.Writer returning EACCES for write error: %v", doneErr)
					doneErr = unix.EACCES
				}
			}
			w.cmps <- stateio.Completion{
				ID:  sub.id,
				N:   done,
				Err: doneErr,
			}
		}
	}
}
