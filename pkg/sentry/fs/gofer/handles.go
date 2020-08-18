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

package gofer

import (
	"io"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/p9"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/secio"
	"gvisor.dev/gvisor/pkg/sentry/fs"
)

// handles are the open handles of a gofer file. They are reference counted to
// support open handle sharing between files for read only filesystems.
//
// If Host != nil then it will be used exclusively over File.
type handles struct {
	refs.AtomicRefCount

	// File is a p9.File handle. Must not be nil.
	File contextFile

	// Host is an *fd.FD handle. May be nil.
	Host *fd.FD

	// isHostBorrowed tells whether 'Host' is owned or borrowed. If owned, it's
	// closed on destruction, otherwise it's released.
	isHostBorrowed bool
}

// DecRef drops a reference on handles.
func (h *handles) DecRef() {
	ctx := context.Background()
	h.DecRefWithDestructor(ctx, func(context.Context) {
		if h.Host != nil {
			if h.isHostBorrowed {
				h.Host.Release()
			} else {
				if err := h.Host.Close(); err != nil {
					log.Warningf("error closing host file: %v", err)
				}
			}
		}
		if err := h.File.close(ctx); err != nil {
			log.Warningf("error closing p9 file: %v", err)
		}
	})
}

func newHandles(ctx context.Context, client *p9.Client, file contextFile, flags fs.FileFlags) (*handles, error) {
	_, newFile, err := file.walk(ctx, nil)
	if err != nil {
		return nil, err
	}

	var p9flags p9.OpenFlags
	switch {
	case flags.Read && flags.Write:
		p9flags = p9.ReadWrite
	case flags.Read && !flags.Write:
		p9flags = p9.ReadOnly
	case !flags.Read && flags.Write:
		p9flags = p9.WriteOnly
	default:
		panic("impossible fs.FileFlags")
	}
	if flags.Truncate && p9.VersionSupportsOpenTruncateFlag(client.Version()) {
		p9flags |= p9.OpenTruncate
	}

	hostFile, _, _, err := newFile.open(ctx, p9flags)
	if err != nil {
		newFile.close(ctx)
		return nil, err
	}
	h := handles{
		File: newFile,
		Host: hostFile,
	}
	h.EnableLeakCheck("gofer.handles")
	return &h, nil
}

type handleReadWriter struct {
	ctx context.Context
	h   *handles
	off int64
}

func (h *handles) readWriterAt(ctx context.Context, offset int64) *handleReadWriter {
	return &handleReadWriter{ctx, h, offset}
}

// ReadToBlocks implements safemem.Reader.ReadToBlocks.
func (rw *handleReadWriter) ReadToBlocks(dsts safemem.BlockSeq) (uint64, error) {
	var r io.Reader
	if rw.h.Host != nil {
		r = secio.NewOffsetReader(rw.h.Host, rw.off)
	} else {
		r = &p9.ReadWriterFile{File: rw.h.File.file, Offset: uint64(rw.off)}
	}

	rw.ctx.UninterruptibleSleepStart(false)
	defer rw.ctx.UninterruptibleSleepFinish(false)
	n, err := safemem.FromIOReader{r}.ReadToBlocks(dsts)
	rw.off += int64(n)
	return n, err
}

// WriteFromBlocks implements safemem.Writer.WriteFromBlocks.
func (rw *handleReadWriter) WriteFromBlocks(srcs safemem.BlockSeq) (uint64, error) {
	var w io.Writer
	if rw.h.Host != nil {
		w = secio.NewOffsetWriter(rw.h.Host, rw.off)
	} else {
		w = &p9.ReadWriterFile{File: rw.h.File.file, Offset: uint64(rw.off)}
	}

	rw.ctx.UninterruptibleSleepStart(false)
	defer rw.ctx.UninterruptibleSleepFinish(false)
	n, err := safemem.FromIOWriter{w}.WriteFromBlocks(srcs)
	rw.off += int64(n)
	return n, err
}
