// Copyright 2020 The gVisor Authors.
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

package kernel

import (
	"fmt"
	"io"
	"sync"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/coverage"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/mm"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/pkg/syserror"
)

// kcovAreaSizeMax is the maximum number of uint64 entries allowed in the kcov
// area. On Linux, the maximum is INT_MAX / 8.
const kcovAreaSizeMax = 10 * 1024 * 1024

// Kcov provides kernel coverage data to userspace through a memory-mapped
// region, as kcov does in Linux.
//
// To give the illusion that the data is always up to date, we update the shared
// memory every time before we return to userspace.
type Kcov struct {
	// mfp provides application memory. It is immutable after creation.
	mfp pgalloc.MemoryFileProvider

	// mu protects all of the fields below.
	mu sync.RWMutex

	// mode is the current kcov mode.
	mode uint8

	// size is the size of the mapping through which the kernel conveys coverage
	// information to userspace.
	size uint64

	// owningTask is the task that currently owns coverage data on the system. The
	// interface for kcov essentially requires that coverage is only going to a
	// single task. Note that kcov should only generate coverage data for the
	// owning task, but we currently generate global coverage.
	owningTask *Task

	// count is a locally cached version of the first uint64 in the kcov data,
	// which is the number of subsequent entries representing PCs.
	//
	// It is used with kcovInode.countBlock(), to copy in/out the first element of
	// the actual data in an efficient manner, avoid boilerplate, and prevent
	// accidental garbage escapes by the temporary counts.
	count uint64

	mappable *mm.SpecialMappable
}

// NewKcov creates and returns a Kcov instance.
func (k *Kernel) NewKcov() *Kcov {
	return &Kcov{
		mfp: k,
	}
}

var coveragePool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 0)
	},
}

// TaskWork implements TaskWorker.TaskWork.
func (kcov *Kcov) TaskWork(t *Task) {
	kcov.mu.Lock()
	defer kcov.mu.Unlock()

	if kcov.mode != linux.KCOV_MODE_TRACE_PC {
		return
	}

	rw := &kcovReadWriter{
		mf: kcov.mfp.MemoryFile(),
		fr: kcov.mappable.FileRange(),
	}

	// Read in the PC count.
	if _, err := safemem.ReadFullToBlocks(rw, kcov.countBlock()); err != nil {
		panic(fmt.Sprintf("Internal error reading count from kcov area: %v", err))
	}

	rw.off = 8 * (1 + kcov.count)
	n := coverage.ConsumeCoverageData(&kcovIOWriter{rw})

	// Update the pc count, based on the number of entries written. Note that if
	// we reached the end of the kcov area, we may not have written everything in
	// output.
	kcov.count += uint64(n / 8)
	rw.off = 0
	if _, err := safemem.WriteFullFromBlocks(rw, kcov.countBlock()); err != nil {
		panic(fmt.Sprintf("Internal error writing count to kcov area: %v", err))
	}

	// Re-register for future work.
	t.RegisterWork(kcov)
}

// InitTrace performs the KCOV_INIT_TRACE ioctl.
func (kcov *Kcov) InitTrace(size uint64) error {
	kcov.mu.Lock()
	defer kcov.mu.Unlock()

	if kcov.mode != linux.KCOV_MODE_DISABLED {
		return syserror.EBUSY
	}

	// To simplify all the logic around mapping, we require that the length of the
	// shared region is a multiple of the system page size.
	if (8*size)&(hostarch.PageSize-1) != 0 {
		return linuxerr.EINVAL
	}

	// We need space for at least two uint64s to hold current position and a
	// single PC.
	if size < 2 || size > kcovAreaSizeMax {
		return linuxerr.EINVAL
	}

	kcov.size = size
	kcov.mode = linux.KCOV_MODE_INIT
	return nil
}

// EnableTrace performs the KCOV_ENABLE_TRACE ioctl.
func (kcov *Kcov) EnableTrace(ctx context.Context, traceKind uint8) error {
	t := TaskFromContext(ctx)
	if t == nil {
		panic("kcovInode.EnableTrace() cannot be used outside of a task goroutine")
	}

	kcov.mu.Lock()
	defer kcov.mu.Unlock()

	// KCOV_ENABLE must be preceded by KCOV_INIT_TRACE and an mmap call.
	if kcov.mode != linux.KCOV_MODE_INIT || kcov.mappable == nil {
		return linuxerr.EINVAL
	}

	switch traceKind {
	case linux.KCOV_TRACE_PC:
		kcov.mode = linux.KCOV_MODE_TRACE_PC
	case linux.KCOV_TRACE_CMP:
		// We do not support KCOV_MODE_TRACE_CMP.
		return syserror.ENOTSUP
	default:
		return linuxerr.EINVAL
	}

	if kcov.owningTask != nil && kcov.owningTask != t {
		return syserror.EBUSY
	}

	kcov.owningTask = t
	t.SetKcov(kcov)
	t.RegisterWork(kcov)

	// Clear existing coverage data; the task expects to read only coverage data
	// from the time it is activated.
	coverage.ClearCoverageData()
	return nil
}

// DisableTrace performs the KCOV_DISABLE_TRACE ioctl.
func (kcov *Kcov) DisableTrace(ctx context.Context) error {
	kcov.mu.Lock()
	defer kcov.mu.Unlock()

	t := TaskFromContext(ctx)
	if t == nil {
		panic("kcovInode.EnableTrace() cannot be used outside of a task goroutine")
	}

	if t != kcov.owningTask {
		return linuxerr.EINVAL
	}
	kcov.mode = linux.KCOV_MODE_INIT
	kcov.owningTask = nil
	if kcov.mappable != nil {
		kcov.mappable.DecRef(ctx)
		kcov.mappable = nil
	}
	return nil
}

// Clear resets the mode and clears the owning task and memory mapping for kcov.
// It is called when the fd corresponding to kcov is closed. Note that the mode
// needs to be set so that the next call to kcov.TaskWork() will exit early.
func (kcov *Kcov) Clear(ctx context.Context) {
	kcov.mu.Lock()
	kcov.mode = linux.KCOV_MODE_INIT
	kcov.owningTask = nil
	if kcov.mappable != nil {
		kcov.mappable.DecRef(ctx)
		kcov.mappable = nil
	}
	kcov.mu.Unlock()
}

// OnTaskExit is called when the owning task exits. It is similar to
// kcov.Clear(), except the memory mapping is not cleared, so that the same
// mapping can be used in the future if kcov is enabled again by another task.
func (kcov *Kcov) OnTaskExit() {
	kcov.mu.Lock()
	kcov.mode = linux.KCOV_MODE_INIT
	kcov.owningTask = nil
	kcov.mu.Unlock()
}

// ConfigureMMap is called by the vfs.FileDescription for this kcov instance to
// implement vfs.FileDescription.ConfigureMMap.
func (kcov *Kcov) ConfigureMMap(ctx context.Context, opts *memmap.MMapOpts) error {
	kcov.mu.Lock()
	defer kcov.mu.Unlock()

	if kcov.mode != linux.KCOV_MODE_INIT {
		return linuxerr.EINVAL
	}

	if kcov.mappable == nil {
		// Set up the kcov area.
		fr, err := kcov.mfp.MemoryFile().Allocate(kcov.size*8, usage.Anonymous)
		if err != nil {
			return err
		}

		// Get the thread id for the mmap name.
		t := TaskFromContext(ctx)
		if t == nil {
			panic("ThreadFromContext returned nil")
		}
		// For convenience, a special mappable is used here. Note that these mappings
		// will look different under /proc/[pid]/maps than they do on Linux.
		kcov.mappable = mm.NewSpecialMappable(fmt.Sprintf("[kcov:%d]", t.ThreadID()), kcov.mfp, fr)
	}
	kcov.mappable.IncRef()
	opts.Mappable = kcov.mappable
	opts.MappingIdentity = kcov.mappable
	return nil
}

// kcovReadWriter implements safemem.Reader and safemem.Writer.
type kcovReadWriter struct {
	off uint64
	mf  *pgalloc.MemoryFile
	fr  memmap.FileRange
}

// ReadToBlocks implements safemem.Reader.ReadToBlocks.
func (rw *kcovReadWriter) ReadToBlocks(dsts safemem.BlockSeq) (uint64, error) {
	if dsts.IsEmpty() {
		return 0, nil
	}

	// Limit the read to the kcov range and check for overflow.
	if rw.fr.Length() <= rw.off {
		return 0, io.EOF
	}
	start := rw.fr.Start + rw.off
	end := rw.fr.Start + rw.fr.Length()
	if rend := start + dsts.NumBytes(); rend < end {
		end = rend
	}

	// Get internal mappings.
	bs, err := rw.mf.MapInternal(memmap.FileRange{start, end}, hostarch.Read)
	if err != nil {
		return 0, err
	}

	// Copy from internal mappings.
	n, err := safemem.CopySeq(dsts, bs)
	rw.off += n
	return n, err
}

// WriteFromBlocks implements safemem.Writer.WriteFromBlocks.
func (rw *kcovReadWriter) WriteFromBlocks(srcs safemem.BlockSeq) (uint64, error) {
	if srcs.IsEmpty() {
		return 0, nil
	}

	// Limit the write to the kcov area and check for overflow.
	if rw.fr.Length() <= rw.off {
		return 0, io.EOF
	}
	start := rw.fr.Start + rw.off
	end := rw.fr.Start + rw.fr.Length()
	if wend := start + srcs.NumBytes(); wend < end {
		end = wend
	}

	// Get internal mapping.
	bs, err := rw.mf.MapInternal(memmap.FileRange{start, end}, hostarch.Write)
	if err != nil {
		return 0, err
	}

	// Copy to internal mapping.
	n, err := safemem.CopySeq(bs, srcs)
	rw.off += n
	return n, err
}

// kcovIOWriter implements io.Writer as a basic wrapper over kcovReadWriter.
type kcovIOWriter struct {
	rw *kcovReadWriter
}

// Write implements io.Writer.Write.
func (w *kcovIOWriter) Write(p []byte) (int, error) {
	bs := safemem.BlockSeqOf(safemem.BlockFromSafeSlice(p))
	n, err := safemem.WriteFullFromBlocks(w.rw, bs)
	return int(n), err
}
