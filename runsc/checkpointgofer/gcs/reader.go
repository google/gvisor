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
	"io"

	"cloud.google.com/go/storage"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/state/stateio"
	"gvisor.dev/gvisor/pkg/sync"
)

// Reader implements stateio.AsyncReader for a GCS object.
type Reader struct {
	stateio.NoRegisterClientFD

	maxReadBytes uint64
	maxRanges    int
	obj          *storage.ObjectHandle
	subs         chan readSubmission
	cmps         chan stateio.Completion
	cancel       context.CancelCauseFunc
	workers      sync.WaitGroup
}

type readSubmission struct {
	id    int
	off   int64
	total uint64
	dst   stateio.LocalClientRanges
}

// NewReader returns a Reader that reads from the given GCS object.
func NewReader(ctx context.Context, obj *storage.ObjectHandle, maxReadBytes uint64, maxRanges, maxParallel int) *Reader {
	ctx, cancel := context.WithCancelCause(ctx)
	r := &Reader{
		maxReadBytes: maxReadBytes,
		maxRanges:    maxRanges,
		obj:          obj,
		subs:         make(chan readSubmission, maxParallel),
		cmps:         make(chan stateio.Completion, maxParallel),
		cancel:       cancel,
	}
	r.workers.Add(maxParallel)
	for range maxParallel {
		go r.workerMain(ctx)
	}
	return r
}

// Close implements stateio.AsyncReader.Close.
func (r *Reader) Close() error {
	r.cancel(fmt.Errorf("context canceled by Reader.Close"))
	r.workers.Wait()
	return nil
}

// MaxReadBytes implements stateio.AsyncReader.MaxReadBytes.
func (r *Reader) MaxReadBytes() uint64 {
	return r.maxReadBytes
}

// MaxRanges implements stateio.AsyncReader.MaxRanges.
func (r *Reader) MaxRanges() int {
	return r.maxRanges
}

// MaxParallel implements stateio.AsyncReader.MaxParallel.
func (r *Reader) MaxParallel() int {
	return cap(r.subs)
}

// AddRead implements stateio.AsyncReader.AddRead.
func (r *Reader) AddRead(id int, off int64, _ stateio.DestinationFile, _ memmap.FileRange, dstMap []byte) {
	r.subs <- readSubmission{
		id:    id,
		off:   off,
		total: uint64(len(dstMap)),
		dst:   stateio.LocalClientMapping(dstMap),
	}
}

// AddReadv implements stateio.AsyncReader.AddReadv.
func (r *Reader) AddReadv(id int, off int64, total uint64, _ stateio.DestinationFile, _ []memmap.FileRange, dstMaps []unix.Iovec) {
	r.subs <- readSubmission{
		id:    id,
		off:   off,
		total: total,
		dst:   stateio.LocalClientMappings(dstMaps),
	}
}

// Wait implements stateio.AsyncReader.Wait.
func (r *Reader) Wait(cs []stateio.Completion, minCompletions int) ([]stateio.Completion, error) {
	return stateio.CompletionChanWait(r.cmps, cs, minCompletions)
}

func (r *Reader) workerMain(ctx context.Context) {
	defer r.workers.Done()
	obj := r.obj
	for {
		select {
		case <-ctx.Done():
			return
		case sub := <-r.subs:
			rr, err := obj.NewRangeReader(ctx, sub.off, int64(sub.total))
			if err != nil {
				if code, ok := httpCodeFromError(err); ok && code == statusRangeNotSatisfiable {
					err = io.EOF
				} else if ok && isPermissionDeniedCode(code) {
					log.Infof("gcs.Reader returning EACCES for error: %v", err)
					err = unix.EACCES
				} else {
					err = fmt.Errorf("storage.ObjectHandle.NewRangeReader failed: %w", err)
				}
				r.cmps <- stateio.Completion{
					ID:  sub.id,
					Err: err,
				}
				continue
			}
			var done uint64
			var doneErr error
			for _, dst := range sub.dst.Mappings {
				n, err := io.ReadFull(rr, dst)
				done += uint64(n)
				if err != nil {
					if err == io.ErrUnexpectedEOF {
						err = io.EOF
					}
					doneErr = err
					break
				}
			}
			r.cmps <- stateio.Completion{
				ID:  sub.id,
				N:   done,
				Err: doneErr,
			}
			obj = obj.ReadHandle(rr.ReadHandle()) // reuse handle for future reads
			rr.Close()
		}
	}
}
