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
	"sort"
	"sync"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/mm"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"

	// With coverage enabled, bazel uses the go cover tool manually to generate
	// instrumented files with --collect_coverage_data. It also injects a hook
	// that registers all coverage data with the coverdata package, which is
	// exactly what we want to expose coverage to userspace.
	"github.com/bazelbuild/rules_go/go/tools/coverdata"
)

// kcovAreaSizeMax is the maximum number of uint64 entries allowed in the kcov
// area. On Linux, the maximum is INT_MAX / 8.
const kcovAreaSizeMax = 10 * 1024 * 1024

// Kcov provides kernel coverage data to userspace through a memory-mapped region,
// much like kcov in Linux. In native Linux, a kernel configuration is set that
// compiles the kernel with a custom function that is called at the beginning
// of every basic block, which updates the memory-mapped coverage information.
// The Go coverage tool does not allow us to inject arbitrary instructions into
// basic blocks, but it does provide can transfer to userspace through a memory
// mapping. To give the illusion that the data is always up to date, we update
// the shared memory every time before we return to userspace. Coverage can be
// enabled by calling bazel build/test with --collect_coverage_data and
// --instrumentation_filter with the desired coverage surface.
type Kcov struct {
	mu sync.RWMutex

	mode uint8

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

	// mfp provides application memory.
	mfp pgalloc.MemoryFileProvider

	mappable *mm.SpecialMappable
}

// NewKcov creates and returns a Kcov instance.
func NewKcov(mfp pgalloc.MemoryFileProvider) *Kcov {
	return &Kcov{
		mfp: mfp,
	}
}

var coveragePool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 0)
	},
}

// TaskWork implements TaskWorker.TaskWork.
func (k *Kcov) TaskWork(t *Task) {
	k.mu.Lock()
	defer k.mu.Unlock()

	// Only copy to the active task.
	if k.owningTask != t {
		return
	}

	rw := &kcovReadWriter{
		mf: k.mfp.MemoryFile(),
		fr: k.mappable.FileRange(),
	}

	// Read in the PC count.
	if _, err := safemem.ReadFullToBlocks(rw, k.countBlock()); err != nil {
		panic(fmt.Sprintf("Internal error reading count from kcov area: %v", err))
	}

	output := coveragePool.Get().([]byte)
	defer coveragePool.Put(output)
	output = consumeCoverageData(output[:0])

	if len(output) == 0 {
		// An empty profile indicates that coverage is not enabled, in which case
		// there shouldn't be any task work registered.
		panic("kcov task work is registered, but no coverage data was found")
	}

	// TODO(deandeng): Write out the new entries.
	bs := safemem.BlockSeqOf(safemem.BlockFromSafeSlice(output))
	rw.off = 8 * (1 + k.count)
	n, err := safemem.WriteFullFromBlocks(rw, bs)
	// Ignore EOF; it's ok if we attempted to write more than we can hold.
	if err != nil && err != io.EOF {
		panic(fmt.Sprintf("Internal error writing PCs to kcov area: %v", err))
	}

	// Update the pc count, based on the number of entries written. Note that if
	// we reached the end of the kcov area, we may not have written everything in
	// output.
	k.count += n / 8
	rw.off = 0
	if _, err := safemem.WriteFullFromBlocks(rw, k.countBlock()); err != nil {
		panic(fmt.Sprintf("Internal error writing count to kcov area: %v", err))
	}

	// Re-register for future work.
	t.RegisterWork(k)
}

// InitTrace performs the KCOV_INIT_TRACE ioctl.
func (k *Kcov) InitTrace(size uint64) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.mode != linux.KCOV_MODE_DISABLED {
		return syserror.EBUSY
	}

	// To simplify all the logic around mapping, we require that the length of the
	// shared region is a multiple of the system page size.
	if size&usermem.PageSize != 0 {
		return syserror.EINVAL
	}

	// We need space for at least two uint64s to hold current position and a
	// single PC.
	if size < 2 || size > kcovAreaSizeMax {
		return syserror.EINVAL
	}

	k.size = size
	k.mode = linux.KCOV_MODE_INIT
	return nil
}

// EnableTrace performs the KCOV_ENABLE_TRACE ioctl.
func (k *Kcov) EnableTrace(ctx context.Context, traceMode uint8) error {
	t := TaskFromContext(ctx)
	if t == nil {
		panic("kcovInode.EnableTrace() cannot be used outside of a task goroutine")
	}

	k.mu.Lock()
	defer k.mu.Unlock()

	// KCOV_ENABLE must be preceded by KCOV_INIT_TRACE and an mmap call.
	if k.mode != linux.KCOV_MODE_INIT || k.mappable == nil {
		return syserror.EINVAL
	}

	switch traceMode {
	case linux.KCOV_TRACE_PC:
		k.mode = traceMode
	case linux.KCOV_TRACE_CMP:
		// We do not support KCOV_MODE_TRACE_CMP.
		return syserror.ENOTSUP
	default:
		return syserror.EINVAL
	}

	if k.owningTask != nil && k.owningTask != t {
		return syserror.EBUSY
	}

	k.owningTask = t
	t.RegisterWork(k)

	// Clear existing coverage data; the task expects to read only coverage data
	// from the time it is activated.
	clearCoverageData()
	return nil
}

// DisableTrace performs the KCOV_DISABLE_TRACE ioctl.
func (k *Kcov) DisableTrace(ctx context.Context) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	t := TaskFromContext(ctx)
	if t == nil {
		panic("kcovInode.EnableTrace() cannot be used outside of a task goroutine")
	}

	if t != k.owningTask {
		return syserror.EINVAL
	}
	k.owningTask = nil
	k.mode = linux.KCOV_MODE_INIT
	k.resetLocked()
	return nil
}

// Reset is called when the owning task exits.
func (k *Kcov) Reset() {
	k.mu.Lock()
	k.resetLocked()
	k.mu.Unlock()
}

// The kcov instance is reset when the owning task exits or when tracing is
// disabled.
func (k *Kcov) resetLocked() {
	k.owningTask = nil
	if k.mappable != nil {
		//k.mappable.DecRef() //TODO(deandeng): dec ref? Or keep the mmap'd region active? Currently, we are getting ref count panic.
		k.mappable = nil
	}
}

// ConfigureMMap is called by the vfs.FileDescription for this kcov instance to
// implement vfs.FileDescription.ConfigureMMap.
func (k *Kcov) ConfigureMMap(ctx context.Context, opts *memmap.MMapOpts) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.mode != linux.KCOV_MODE_INIT {
		return syserror.EINVAL
	}

	if k.mappable == nil {
		// Set up the kcov area.
		fr, err := k.mfp.MemoryFile().Allocate(k.size*8, usage.System) // TODO(deandeng): is the usage.Kind correct?
		if err != nil {
			return err
		}
		k.mappable = mm.NewSpecialMappable("/sys/kernel/debug/kcov", k.mfp, fr) // TODO(deandeng): is this the right mmap name? Might need to specify tid if there are multiple instances/mappings
	}
	opts.Mappable = k.mappable
	opts.MappingIdentity = k.mappable
	return nil
}

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

	// TODO(deandeng): synchronization?

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
	bs, err := rw.mf.MapInternal(memmap.FileRange{start, end}, usermem.Read)
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
	// TODO(deandeng): synchronization?
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
	bs, err := rw.mf.MapInternal(memmap.FileRange{start, end}, usermem.Write)
	if err != nil {
		return 0, err
	}

	// Copy to internal mapping.
	n, err := safemem.CopySeq(bs, srcs)
	rw.off += n
	return n, err
}

var globalData struct {
	// files is a well-ordered set of PCs, corresponding to the
	// well-ordered set of files calculated at start-up.
	files []string

	// syntheticPCs are calculated at startup, and correspond to the file
	// index, and the block index.
	syntheticPCs [][]uint64
}

// clearCoverageData clears existing coverage data.
func clearCoverageData() {
	for _, counters := range coverdata.Cover.Counters {
		for index := 0; index < len(counters); index++ {
			atomic.StoreUint32(&counters[index], 0)
		}
	}
}

// consumeCoverageData builds the collection of covered PCs.
//
// All coverage data is reset when this function is run.
//
// Precondition: output must be zero sized.
func consumeCoverageData(output []byte) []byte {
	for fileIndex, file := range globalData.files {
		counters := coverdata.Cover.Counters[file]
		for index := 0; index < len(counters); index++ {
			val := atomic.SwapUint32(&counters[index], 0)
			if val != 0 {
				// Calculate the synthetic PC.
				pc := globalData.syntheticPCs[fileIndex][index]

				// Pack to the output slice as required.
				var pcBuffer [8]byte
				usermem.ByteOrder.PutUint64(pcBuffer[:], pc)
				output = append(output, pcBuffer[:]...)
			}
		}
	}
	return output
}

func init() {
	// Initialize globalData.
	//
	// First, order all files. Then calculate synthetic PCs for every block
	// (using the well-defined ordering for files as well).
	for file := range coverdata.Cover.Blocks {
		globalData.files = append(globalData.files, file)
	}
	sort.Strings(globalData.files)

	// nextSyntheticPC is the first PC that we generate for a block.
	//
	// This uses a standard-looking kernel range for simplicity.
	var nextSyntheticPC uint64 = 0xffffffff80000000
	for _, file := range globalData.files {
		blocks := coverdata.Cover.Blocks[file]
		thisFile := make([]uint64, 0, len(blocks))
		for range blocks {
			thisFile = append(thisFile, nextSyntheticPC)
			nextSyntheticPC++ // Advance.
		}
		globalData.syntheticPCs = append(globalData.syntheticPCs, thisFile)
	}
}
