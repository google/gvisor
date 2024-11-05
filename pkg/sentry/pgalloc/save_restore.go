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

package pgalloc

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"runtime"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/aio"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/bitmap"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/goid"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/ringdeque"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/pkg/state"
	"gvisor.dev/gvisor/pkg/state/wire"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/syncevent"
)

// SaveOpts provides options to MemoryFile.SaveTo().
type SaveOpts struct {
	// If ExcludeCommittedZeroPages is true, SaveTo() will scan both committed
	// and possibly-committed pages to find zero pages, whose contents are
	// saved implicitly rather than explicitly to reduce checkpoint size. If
	// ExcludeCommittedZeroPages is false, SaveTo() will scan only
	// possibly-committed pages to find zero pages.
	//
	// Enabling ExcludeCommittedZeroPages will usually increase the time taken
	// by SaveTo() (due to the larger number of pages that must be scanned),
	// but may instead improve SaveTo() and LoadFrom() time, and checkpoint
	// size, if the application has many committed zero pages.
	ExcludeCommittedZeroPages bool
}

// SaveTo writes f's state to the given stream.
func (f *MemoryFile) SaveTo(ctx context.Context, w io.Writer, pw io.Writer, opts SaveOpts) error {
	if err := f.AwaitLoadAll(); err != nil {
		return fmt.Errorf("previous async page loading failed: %w", err)
	}

	// Wait for memory release.
	f.mu.Lock()
	defer f.mu.Unlock()
	for f.haveWaste {
		f.mu.Unlock()
		runtime.Gosched()
		f.mu.Lock()
	}

	// Ensure that there are no pending evictions.
	if len(f.evictable) != 0 {
		panic(fmt.Sprintf("evictions still pending for %d users; call StartEvictions and WaitForEvictions before SaveTo", len(f.evictable)))
	}

	// Ensure that all pages that contain non-zero bytes are marked
	// known-committed, since we only store known-committed pages below.
	timeScanStart := time.Now()
	zeroPage := make([]byte, hostarch.PageSize)
	var (
		decommitWarnOnce  sync.Once
		decommitPendingFR memmap.FileRange
		scanTotal         uint64
		decommitTotal     uint64
		decommitCount     uint64
	)
	decommitNow := func(fr memmap.FileRange) {
		decommitTotal += fr.Length()
		decommitCount++
		if err := f.decommitFile(fr); err != nil {
			// This doesn't impact the correctness of saved memory, it just
			// means that we're incrementally more likely to OOM. Complain, but
			// don't abort saving.
			decommitWarnOnce.Do(func() {
				log.Warningf("Decommitting MemoryFile offsets %v while saving failed: %v", fr, err)
			})
		}
	}
	decommitAddPage := func(off uint64) {
		// Invariants:
		// (1) All of decommitPendingFR lies within a single huge page.
		// (2) decommitPendingFR.End is hugepage-aligned iff
		// decommitPendingFR.Length() == 0.
		end := off + hostarch.PageSize
		if decommitPendingFR.End == off {
			// Merge with the existing range. By invariants, the page {off,
			// end} must be within the same huge page as the rest of
			// decommitPendingFR.
			decommitPendingFR.End = end
		} else {
			// Decommit the existing range and start a new one.
			if decommitPendingFR.Length() != 0 {
				decommitNow(decommitPendingFR)
			}
			decommitPendingFR = memmap.FileRange{off, end}
		}
		// Maintain invariants by decommitting if we've reached the end of the
		// containing huge page.
		if hostarch.IsHugePageAligned(end) {
			decommitNow(decommitPendingFR)
			decommitPendingFR = memmap.FileRange{}
		}
	}
	err := f.updateUsageLocked(nil, opts.ExcludeCommittedZeroPages, func(bs []byte, committed []byte, off uint64, wasCommitted bool) error {
		scanTotal += uint64(len(bs))
		for pgoff := 0; pgoff < len(bs); pgoff += hostarch.PageSize {
			i := pgoff / hostarch.PageSize
			pg := bs[pgoff : pgoff+hostarch.PageSize]
			if !bytes.Equal(pg, zeroPage) {
				committed[i] = 1
				continue
			}
			committed[i] = 0
			if !wasCommitted {
				// Reading the page may have caused it to be committed;
				// decommit it to reduce memory usage.
				decommitAddPage(off + uint64(pgoff))
			}
		}
		return nil
	})
	if decommitPendingFR.Length() != 0 {
		decommitNow(decommitPendingFR)
		decommitPendingFR = memmap.FileRange{}
	}
	if err != nil {
		return err
	}
	log.Infof("MemoryFile(%p): saving scanned %d bytes, decommitted %d bytes in %d syscalls, %s", f, scanTotal, decommitTotal, decommitCount, time.Since(timeScanStart))

	// Save metadata.
	timeMetadataStart := time.Now()
	if _, err := state.Save(ctx, w, &f.unwasteSmall); err != nil {
		return err
	}
	if _, err := state.Save(ctx, w, &f.unwasteHuge); err != nil {
		return err
	}
	if _, err := state.Save(ctx, w, &f.unfreeSmall); err != nil {
		return err
	}
	if _, err := state.Save(ctx, w, &f.unfreeHuge); err != nil {
		return err
	}
	if _, err := state.Save(ctx, w, &f.subreleased); err != nil {
		return err
	}
	if _, err := state.Save(ctx, w, &f.memAcct); err != nil {
		return err
	}
	if _, err := state.Save(ctx, w, &f.knownCommittedBytes); err != nil {
		return err
	}
	if _, err := state.Save(ctx, w, &f.commitSeq); err != nil {
		return err
	}
	if _, err := state.Save(ctx, w, f.chunks.Load()); err != nil {
		return err
	}
	log.Infof("MemoryFile(%p): saved metadata in %s", f, time.Since(timeMetadataStart))

	// Dump out committed pages.
	ww := wire.Writer{Writer: w}
	timePagesStart := time.Now()
	savedBytes := uint64(0)
	for maseg := f.memAcct.FirstSegment(); maseg.Ok(); maseg = maseg.NextSegment() {
		if !maseg.ValuePtr().knownCommitted {
			continue
		}
		// Write a header to distinguish from objects.
		if err := state.WriteHeader(&ww, uint64(maseg.Range().Length()), false); err != nil {
			return err
		}
		// Write out data.
		var ioErr error
		f.forEachMappingSlice(maseg.Range(), func(s []byte) {
			if ioErr != nil {
				return
			}
			_, ioErr = pw.Write(s)
		})
		if ioErr != nil {
			return ioErr
		}
		savedBytes += maseg.Range().Length()
	}
	durPages := time.Since(timePagesStart)
	log.Infof("MemoryFile(%p): saved pages in %s (%d bytes, %f bytes/second)", f, durPages, savedBytes, float64(savedBytes)/durPages.Seconds())

	return nil
}

// MarkSavable marks f as savable.
func (f *MemoryFile) MarkSavable() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.savable = true
}

// IsSavable returns true if f is savable.
func (f *MemoryFile) IsSavable() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.savable
}

// RestoreID returns the restore ID for f.
func (f *MemoryFile) RestoreID() string {
	return f.opts.RestoreID
}

// LoadOpts provides options to MemoryFile.LoadFrom().
type LoadOpts struct {
	// If PagesFile is not nil, then page contents will be read from PagesFile,
	// starting at PagesFileOffset, rather than from r. If LoadFrom returns a
	// nil error, it increments PagesFileOffset by the number of bytes that
	// will be read out of PagesFile. PagesFile may be read even after LoadFrom
	// returns; OnAsyncPageLoadStart will be called before reading from
	// PagesFile begins, and OnAsyncPageLoadDone will be called after all reads
	// are complete. Callers must ensure that PagesFile remains valid until
	// OnAsyncPageLoadDone is called.
	PagesFile            *fd.FD
	PagesFileOffset      uint64
	OnAsyncPageLoadStart func()
	OnAsyncPageLoadDone  func(error)
}

// LoadFrom loads MemoryFile state from the given stream.
func (f *MemoryFile) LoadFrom(ctx context.Context, r io.Reader, opts *LoadOpts) error {
	timeMetadataStart := time.Now()

	// Clear sets since non-empty sets will panic if loaded into.
	f.unwasteSmall.RemoveAll()
	f.unwasteHuge.RemoveAll()
	f.unfreeSmall.RemoveAll()
	f.unfreeHuge.RemoveAll()
	f.memAcct.RemoveAll()

	// Load metadata.
	if _, err := state.Load(ctx, r, &f.unwasteSmall); err != nil {
		return err
	}
	if _, err := state.Load(ctx, r, &f.unwasteHuge); err != nil {
		return err
	}
	if _, err := state.Load(ctx, r, &f.unfreeSmall); err != nil {
		return err
	}
	if _, err := state.Load(ctx, r, &f.unfreeHuge); err != nil {
		return err
	}
	if _, err := state.Load(ctx, r, &f.subreleased); err != nil {
		return err
	}
	if _, err := state.Load(ctx, r, &f.memAcct); err != nil {
		return err
	}
	if _, err := state.Load(ctx, r, &f.knownCommittedBytes); err != nil {
		return err
	}
	if _, err := state.Load(ctx, r, &f.commitSeq); err != nil {
		return err
	}
	var chunks []chunkInfo
	if _, err := state.Load(ctx, r, &chunks); err != nil {
		return err
	}
	f.chunks.Store(&chunks)
	log.Infof("MemoryFile(%p): loaded metadata in %s", f, time.Since(timeMetadataStart))
	if err := f.file.Truncate(int64(len(chunks)) * chunkSize); err != nil {
		return fmt.Errorf("failed to truncate MemoryFile: %w", err)
	}
	// Obtain chunk mappings, then madvise them concurrently with loading data.
	var (
		madviseEnd  atomicbitops.Uint64
		madviseChan = make(chan struct{}, 1)
		madviseWG   sync.WaitGroup
	)
	if len(chunks) != 0 {
		m, _, errno := unix.Syscall6(
			unix.SYS_MMAP,
			0,
			uintptr(len(chunks)*chunkSize),
			unix.PROT_READ|unix.PROT_WRITE,
			unix.MAP_SHARED,
			f.file.Fd(),
			0)
		if errno != 0 {
			return fmt.Errorf("failed to mmap MemoryFile: %w", errno)
		}
		for i := range chunks {
			chunk := &chunks[i]
			chunk.mapping = m
			m += chunkSize
		}
		madviseWG.Add(1)
		go func() {
			defer madviseWG.Done()
			for i := range chunks {
				chunk := &chunks[i]
				f.madviseChunkMapping(chunk.mapping, chunkSize, chunk.huge)
				madviseEnd.Add(chunkSize)
				select {
				case madviseChan <- struct{}{}:
				default:
				}
			}
		}()
	}
	defer madviseWG.Wait()

	// Start async page loading if a pages file has been provided.
	//
	// Future work: In practice, all restored MemoryFiles in a given Kernel
	// will share the same pages file (see Kernel.loadMemoryFiles()), so each
	// MemoryFile will maintain its own AIO queue and async page loader. In
	// addition to resource usage downsides, this means that awaited loads may
	// not be consistently prioritized: they'll be prioritized by their
	// originating MemoryFile, but may compete with unawaited loads from other
	// MemoryFiles. I think the best way to fix this would be to have a single
	// AIO queue and async page loader per pages file (still in this package),
	// and have it schedule reads between multiple MemoryFiles. As of this
	// writing, this doesn't seem to be a problem since our workloads of
	// interest have relatively small root overlay MemoryFiles (the most common
	// private MemoryFile).
	var (
		aplg *aplGoroutine
		apl  *aplShared
	)
	if opts.PagesFile != nil {
		aplg = &aplGoroutine{
			f:            f,
			q:            aio.NewGoQueue(aplQueueCapacity),
			doneCallback: opts.OnAsyncPageLoadDone,
			qavail:       aplQueueCapacity,
			fd:           int32(opts.PagesFile.FD()),
			opsBusy:      bitmap.New(aplQueueCapacity),
		}
		apl = &aplg.apl
		// Mark ops in opsBusy that don't actually exist as permanently busy.
		for i, n := aplQueueCapacity, aplg.opsBusy.Size(); i < n; i++ {
			aplg.opsBusy.Add(uint32(i))
		}
		aplg.lfStatus.Init()
		defer aplg.lfStatus.Notify(aplLFDone)
		f.asyncPageLoad.Store(apl)
		if opts.OnAsyncPageLoadStart != nil {
			opts.OnAsyncPageLoadStart()
		}
		go aplg.main()
	}

	// Load committed pages.
	wr := wire.Reader{Reader: r}
	timePagesStart := time.Now()
	loadedBytes := uint64(0)
	defer func() { opts.PagesFileOffset += loadedBytes }()
	for maseg := f.memAcct.FirstSegment(); maseg.Ok(); maseg = maseg.NextSegment() {
		if !maseg.ValuePtr().knownCommitted {
			continue
		}
		// Verify header.
		length, object, err := state.ReadHeader(&wr)
		if err != nil {
			return fmt.Errorf("failed to read header: %w", err)
		}
		if object {
			// Not expected.
			return fmt.Errorf("unexpected object")
		}
		maFR := maseg.Range()
		amount := maFR.Length()
		if length != amount {
			// Size mismatch.
			return fmt.Errorf("mismatched segment: expected %d, got %d", amount, length)
		}
		// Wait for all chunks spanned by this segment to be madvised.
		for madviseEnd.Load() < maFR.End {
			<-madviseChan
		}
		if apl != nil {
			// Record where to read data.
			apl.mu.Lock()
			apl.unloaded.InsertRange(maFR, aplUnloadedInfo{
				off: opts.PagesFileOffset + loadedBytes,
			})
			apl.mu.Unlock()
			aplg.lfStatus.Notify(aplLFPending)
		} else {
			// Read data.
			var ioErr error
			f.forEachMappingSlice(maFR, func(s []byte) {
				if ioErr != nil {
					return
				}
				_, ioErr = io.ReadFull(r, s)
			})
			if ioErr != nil {
				return fmt.Errorf("failed to read pages: %w", ioErr)
			}
		}

		// Update accounting for restored pages. We need to do this here since
		// these segments are marked as "known committed", and will be skipped
		// over on accounting scans.
		loadedBytes += amount
		if !f.opts.DisableMemoryAccounting {
			usage.MemoryAccounting.Inc(amount, maseg.ValuePtr().kind, maseg.ValuePtr().memCgID)
		}
	}
	durPages := time.Since(timePagesStart)
	if apl != nil {
		log.Infof("MemoryFile(%p): loaded page file offsets in %s; async loading %d bytes", f, durPages, loadedBytes)
	} else {
		log.Infof("MemoryFile(%p): loaded pages in %s (%d bytes, %f bytes/second)", f, durPages, loadedBytes, float64(loadedBytes)/durPages.Seconds())
	}

	return nil
}

// aplShared holds asynchronous page loading state that is shared with
// users of the MemoryFile.
type aplShared struct {
	// minUnloaded is the MemoryFile offset of the first unloaded byte.
	minUnloaded atomicbitops.Uint64

	// mu protects the following fields.
	mu aplSharedMutex

	// If err is not nil, it is an error that has terminated asynchronous page
	// loading. err can only be set by the async page loader goroutine, and can
	// only transition from nil to non-nil once, after which it is immutable.
	err error

	// unloaded tracks pages that have not been loaded.
	unloaded aplUnloadedSet

	// priority contains possibly-unstarted ranges in unloaded with at least
	// one waiter.
	priority ringdeque.Deque[memmap.FileRange]
}

// aplUnloadedInfo is the value type of aplShared.unloaded.
type aplUnloadedInfo struct {
	// off is the offset into the pages file at which the represented pages
	// begin.
	off uint64

	// started is true if a read has been enqueued for these pages.
	started bool

	// waiters queues goroutines waiting for these pages to be loaded.
	waiters []*aplWaiter
}

type aplWaiter struct {
	// wakeup is used by a caller of MemoryFile.awaitLoad() to block until all
	// pages in fr are loaded.
	wakeup syncevent.Waiter
	fr     memmap.FileRange

	// pending is the number of unloaded bytes that this waiter is waiting for.
	pending uint64
}

var aplWaiterPool = sync.Pool{
	New: func() any {
		var w aplWaiter
		w.wakeup.Init()
		return &w
	},
}

// IsAsyncLoading returns true if async page loading is in progress or has
// failed permanently.
func (f *MemoryFile) IsAsyncLoading() bool {
	return f.asyncPageLoad.Load() != nil
}

// AwaitLoadAll blocks until async page loading has completed. If async page
// loading is not in progress, AwaitLoadAll returns immediately.
func (f *MemoryFile) AwaitLoadAll() error {
	if apl := f.asyncPageLoad.Load(); apl != nil {
		return apl.awaitLoad(f, memmap.FileRange{0, hostarch.PageRoundDown(uint64(math.MaxUint64))})
	}
	return nil
}

// awaitLoad blocks until data has been loaded for all pages in fr.
//
// Preconditions: At least one reference must be held on all unloaded pages in
// fr.
func (apl *aplShared) awaitLoad(f *MemoryFile, fr memmap.FileRange) error {
	// Lockless fast path:
	if fr.End <= apl.minUnloaded.Load() {
		return nil
	}

	// fr might not be page-aligned; everything else involved in async page
	// loading requires page-aligned FileRanges.
	fr.Start = hostarch.PageRoundDown(fr.Start)
	fr.End = hostarch.MustPageRoundUp(fr.End)

	apl.mu.Lock()
	if err := apl.err; err != nil {
		if apl.unloaded.IsEmptyRange(fr) {
			// fr is already loaded.
			apl.mu.Unlock()
			return nil
		}
		// A previous error means that fr will never be loaded.
		apl.mu.Unlock()
		return err
	}
	w := aplWaiterPool.Get().(*aplWaiter)
	defer aplWaiterPool.Put(w)
	w.fr = fr
	w.pending = 0
	apl.unloaded.MutateRange(fr, func(ulseg aplUnloadedIterator) bool {
		ul := ulseg.ValuePtr()
		ulFR := ulseg.Range()
		if len(ul.waiters) == 0 && !ul.started {
			apl.priority.PushBack(ulFR)
			if logAwaitedLoads {
				log.Infof("MemoryFile(%p): prioritize %v", f, ulFR)
			}
		}
		ul.waiters = append(ul.waiters, w)
		w.pending += ulFR.Length()
		return true
	})
	pending := w.pending != 0
	apl.mu.Unlock()
	if pending {
		var startWaitTime time.Time
		if logAwaitedLoads {
			startWaitTime = time.Now()
			log.Infof("MemoryFile(%p): awaitLoad goid %d start: %v (%d bytes)", f, goid.Get(), fr, fr.Length())
		}
		w.wakeup.WaitAndAckAll()
		if logAwaitedLoads {
			log.Infof("MemoryFile(%p): awaitLoad goid %d waited %v: %v (%d bytes)", f, goid.Get(), time.Since(startWaitTime), fr, fr.Length())
		}
	}
	return apl.err
}

const (
	// When a pages file is provided, reads from it will be issued
	// asynchronously via an aio.Queue of capacity aplQueueCapacity, and each
	// read will be of size aplReadMaxBytes when possible; reads may be smaller
	// in some circumstances but will never be larger.
	// TODO: Pass these via LoadOpts and make them flag-controlled.
	aplReadMaxBytes  = 256 * 1024
	aplQueueCapacity = 128

	aplOpMaxIovecs = aplReadMaxBytes / hostarch.PageSize
)

// aplGoroutine holds state for the async page loader goroutine.
type aplGoroutine struct {
	apl aplShared
	_   [hostarch.CacheLineSize]byte // padding

	f            *MemoryFile  // immutable
	q            *aio.GoQueue // immutable
	doneCallback func(error)  // immutable

	// lfStatus communicates state from Memory.LoadFrom() to the goroutine.
	lfStatus syncevent.Waiter

	// qavail is unused capacity in q.
	qavail int

	// The async page loader combines multiple loads with contiguous pages file
	// offsets (the common case) into a single read, even if their
	// corresponding memmap.FileRanges and mappings are discontiguous. If curOp
	// is not nil, it is the current aplOp under construction, and curOpID is
	// its index into ops.
	curOp   *aplOp
	curOpID uint32

	// fd is the host file descriptor for the pages file.
	fd int32 // immutable

	// opsBusy tracks which aplOps in ops are in use (correspond to
	// inflight operations or curOp).
	opsBusy bitmap.Bitmap

	// ops stores all aplOps.
	ops [aplQueueCapacity]aplOp
}

// Possible events in aplGoroutine.lfStatus:
const (
	aplLFPending syncevent.Set = 1 << iota
	aplLFDone
)

// aplOp tracks async page load state corresponding to a single AIO read
// operation.
type aplOp struct {
	// total is the number of bytes to be read by the operation.
	total uint64

	// end is the pages file offset at which the read ends.
	end uint64

	// frs() = frsData[:frsLen] are the MemoryFile ranges being loaded.
	frsData [aplOpMaxIovecs]memmap.FileRange
	frsLen  uint8

	// iovecsLen is described below, but stored here to minimize alignment
	// padding.
	iovecsLen uint8

	// If tempRef is true, a temporary reference is held on pages in frs() that
	// should be dropped after completion.
	tempRef bool

	// iovecs() = iovecsData[:iovecsLen] contains mappings of frs().
	iovecsData [aplOpMaxIovecs]unix.Iovec
}

func (op *aplOp) off() int64 {
	return int64(op.end - op.total)
}

func (op *aplOp) frs() []memmap.FileRange {
	return op.frsData[:op.frsLen]
}

func (op *aplOp) iovecs() []unix.Iovec {
	return op.iovecsData[:op.iovecsLen]
}

func (g *aplGoroutine) canEnqueue() bool {
	return g.qavail > 0
}

// Preconditions: g.canEnqueue() == true.
func (g *aplGoroutine) enqueueCurOp() {
	if g.qavail <= 0 {
		panic("queue full")
	}
	op := g.curOp
	if op.total == 0 {
		panic("invalid read of 0 bytes")
	}
	if op.total > aplReadMaxBytes {
		panic(fmt.Sprintf("read of %d bytes exceeds per-read limit of %d bytes", op.total, aplReadMaxBytes))
	}

	g.qavail--
	g.curOp = nil
	if op.iovecsLen == 1 {
		// Perform a non-vectorized read to save an indirection (and
		// userspace-to-kernelspace copy) in the aio.Queue implementation.
		aio.Read(g.q, uint64(g.curOpID), g.fd, op.off(), sliceFromIovec(op.iovecsData[0]))
	} else {
		aio.Readv(g.q, uint64(g.curOpID), g.fd, op.off(), op.iovecs())
	}
	if logAwaitedLoads && !op.tempRef {
		log.Infof("MemoryFile(%p): awaited opid %d start, read %d bytes: %v", g.f, g.curOpID, op.total, op.frs())
	}
}

// Preconditions:
// - g.canEnqueue() == true.
// - fr.Length() > 0.
// - fr must be page-aligned.
func (g *aplGoroutine) enqueueRange(fr memmap.FileRange, off uint64, tempRef bool) uint64 {
	for {
		if g.curOp == nil {
			id, err := g.opsBusy.FirstZero(0)
			if err != nil {
				panic(fmt.Sprintf("all ops busy with qavail=%d: %v", g.qavail, err))
			}
			g.opsBusy.Add(id)
			op := &g.ops[id]
			op.total = 0
			op.frsLen = 0
			op.iovecsLen = 0
			g.curOp = op
			g.curOpID = id
		}
		n := g.combine(fr, off, tempRef)
		if n > 0 {
			return n
		}
		// Flush the existing (conflicting) op and try again with a new one.
		g.enqueueCurOp()
		if !g.canEnqueue() {
			return 0
		}
	}
}

// combine adds as much of the given load as possible to g.curOp and returns
// the number of bytes added.
//
// Preconditions:
// - fr.Length() > 0.
// - fr must be page-aligned.
//
// Postconditions:
// - combine() never returns (0, false).
func (g *aplGoroutine) combine(fr memmap.FileRange, off uint64, tempRef bool) uint64 {
	op := g.curOp
	if op.total != 0 {
		if op.end != off {
			// Non-contiguous in the pages file.
			return 0
		}
		if int(op.frsLen) == len(op.frsData) && op.frsData[op.frsLen-1].End != fr.Start {
			// Non-contiguous in the MemoryFile, and we're out of space for
			// FileRanges.
			return 0
		}
		if op.tempRef != tempRef {
			// Incompatible reference-counting semantics. We could handle this
			// by making tempRef per-FileRange, but it's very unlikely that an
			// awaited load (tempRef=false) will happen to be followed by an
			// unawaited load (tempRef=true) at the correct offset.
			return 0
		}
	}

	// Apply direct length limits.
	n := fr.Length()
	if op.total+n >= aplReadMaxBytes {
		n = aplReadMaxBytes - op.total
	}
	if n == 0 {
		return 0
	}
	fr.End = fr.Start + n

	// Collect iovecs, which may further limit length.
	n = 0
	g.f.forEachMappingSlice(fr, func(bs []byte) {
		if op.iovecsLen > 0 {
			if canMergeIovecAndSlice(op.iovecsData[op.iovecsLen-1], bs) {
				op.iovecsData[op.iovecsLen-1].Len += uint64(len(bs))
				n += uint64(len(bs))
				return
			}
			if int(op.iovecsLen) == len(op.iovecsData) {
				return
			}
		}
		op.iovecsData[op.iovecsLen].Base = &bs[0]
		op.iovecsData[op.iovecsLen].SetLen(len(bs))
		op.iovecsLen++
		n += uint64(len(bs))
	})
	if n == 0 {
		return 0
	}
	fr.End = fr.Start + n

	// With the length decided, finish updating op.
	if op.total == 0 {
		op.end = off
	}
	op.end += n
	op.total += n
	op.tempRef = tempRef
	if op.frsLen > 0 && op.frsData[op.frsLen-1].End == fr.Start {
		op.frsData[op.frsLen-1].End = fr.End
	} else {
		op.frsData[op.frsLen] = fr
		op.frsLen++
	}
	return n
}

func (g *aplGoroutine) main() {
	apl := &g.apl
	f := g.f
	q := g.q
	defer func() {
		// Destroy q first since this synchronously stops inflight I/O.
		q.Destroy()
		// Wake up any remaining waiters so that they can observe apl.err.
		// Leave all segments in unloaded so that new callers of
		// f.awaitLoad(apl) will still observe the correct (permanently
		// unloaded) segments.
		apl.mu.Lock()
		for ulseg := apl.unloaded.FirstSegment(); ulseg.Ok(); ulseg = ulseg.NextSegment() {
			ul := ulseg.ValuePtr()
			ullen := ulseg.Range().Length()
			for _, w := range ul.waiters {
				w.pending -= ullen
				if w.pending == 0 {
					w.wakeup.Notify(1)
				}
			}
			ul.waiters = nil
		}
		apl.mu.Unlock()
		if g.doneCallback != nil {
			g.doneCallback(apl.err)
		}
	}()

	minUnstarted := uint64(0)

	// Storage reused between main loop iterations:
	var completions []aio.Completion
	var wakeups []*aplWaiter
	var decRefs []memmap.FileRange

	dropDelayedDecRefs := func() {
		if len(decRefs) != 0 {
			for _, fr := range decRefs {
				f.DecRef(fr)
			}
			decRefs = decRefs[:0]
		}
	}
	defer dropDelayedDecRefs()

	timeStart := time.Now()
	loadedBytes := uint64(0)
	log.Debugf("MemoryFile(%p): async page loading started", f)
	for {
		// Enqueue as many reads as possible.
		if !g.canEnqueue() {
			panic("main loop invariant failed")
		}
		// Prioritize reading pages with waiters.
		apl.mu.Lock()
		for g.canEnqueue() && !apl.priority.Empty() {
			fr := apl.priority.PopFront()
			// All pages in apl.priority have non-zero waiters and were split
			// around fr by f.awaitLoad(), and apl.unloaded never merges
			// segments with waiters. Thus, we don't need to split around fr
			// again, and fr.Intersect(ulseg.Range()) == ulseg.Range().
			ulseg := apl.unloaded.LowerBoundSegment(fr.Start)
			for ulseg.Ok() && ulseg.Start() < fr.End {
				ul := ulseg.ValuePtr()
				ulFR := ulseg.Range()
				if ul.started {
					fr.Start = ulFR.End
					ulseg = ulseg.NextSegment()
					continue
				}
				// Awaited pages are guaranteed to have a reference held (by
				// f.awaitLoad() precondition), so they can't become waste (which would
				// allow them to be racily released or recycled).
				n := g.enqueueRange(ulFR, ul.off, false /* tempRef */)
				if n == 0 {
					// Try again in the next iteration of the main loop, when
					// we have space in the queue again.
					apl.priority.PushFront(fr)
					break
				}
				ulFR.End = ulFR.Start + n
				ulseg = apl.unloaded.SplitAfter(ulseg, ulFR.End)
				ulseg.ValuePtr().started = true
				fr.Start = ulFR.End
				if fr.Length() > 0 {
					// Cycle the rest of fr to the end of apl.priority. This
					// prevents large awaited reads from starving other
					// waiters.
					apl.priority.PushBack(fr)
					break
				}
				ulseg = ulseg.NextSegment()
			}
		}
		apl.mu.Unlock()
		// Fill remaining queue with reads for pages with no waiters.
		if g.canEnqueue() {
			f.mu.Lock()
			apl.mu.Lock()
			ulseg := apl.unloaded.LowerBoundSegment(minUnstarted)
			for ulseg.Ok() {
				ul := ulseg.ValuePtr()
				ulFR := ulseg.Range()
				if ul.started {
					minUnstarted = ulFR.End
					ulseg = ulseg.NextSegment()
					continue
				}
				// We need to take page references during reading to prevent
				// pages from becoming waste due to concurrent dropping of the
				// last reference.
				n := g.enqueueRange(ulFR, ul.off, true /* tempRef */)
				if n == 0 {
					break
				}
				ulFR.End = ulFR.Start + n
				ulseg = apl.unloaded.SplitAfter(ulseg, ulFR.End)
				ulseg.ValuePtr().started = true
				minUnstarted = ulFR.End
				f.incRefLocked(ulFR)
				if !g.canEnqueue() {
					break
				}
				ulseg = ulseg.NextSegment()
			}
			apl.mu.Unlock()
			f.mu.Unlock()
		}
		// Flush pending op.
		if g.curOp != nil {
			g.enqueueCurOp()
		}

		if g.qavail == q.Cap() {
			// We are out of work to do.
			ev := g.lfStatus.Wait()
			if ev&aplLFPending != 0 {
				// We may have raced with MemoryFile.LoadFrom() inserting into
				// apl.unloaded.
				g.lfStatus.Ack(aplLFPending)
				continue
			}
			if ev&aplLFDone != 0 {
				// MemoryFile.LoadFrom() finished inserting into apl.unloaded,
				// so async page loading has completed successfully.
				apl.minUnloaded.Store(math.MaxUint64)
				f.asyncPageLoad.Store(nil)
				dur := time.Since(timeStart)
				log.Infof("MemoryFile(%p): async page loading completed in %s (%d bytes, %f bytes/second)", f, dur, loadedBytes, float64(loadedBytes)/dur.Seconds())
				return
			}
			panic(fmt.Sprintf("unknown events in lfStatus: %#x", ev))
		}

		// Wait for any number of reads to complete.
		var err error
		completions, err = q.Wait(completions[:0], 1 /* minCompletions */)
		if err != nil {
			log.Warningf("MemoryFile(%p): async page loading: aio.Queue.Wait failed: %v", f, err)
			apl.mu.Lock()
			apl.err = linuxerr.EIO
			apl.mu.Unlock()
			return
		}

		// Process completions.
		apl.mu.Lock()
		for _, c := range completions {
			op := g.ops[c.ID]
			g.opsBusy.Remove(uint32(c.ID))
			g.qavail++
			if op.tempRef {
				// Delay f.DecRef(fr) until after dropping locks. This is
				// required to avoid lock recursion via dropping the last
				// reference => apl.cancelWasteLoad() => apl.mu.Lock().
				decRefs = append(decRefs, op.frs()...)
			}
			if err := c.Err(); err != nil {
				log.Warningf("MemoryFile(%p): async page loading: read for pages %v failed: %v", f, op.frs(), err)
				apl.err = err
				apl.mu.Unlock()
				return
			}
			if uint64(c.Result) != op.total {
				// TODO: Is this something we actually have to worry about? If
				// so, we need to reissue the remainder of the read...
				log.Warningf("MemoryFile(%p): async page loading: read for pages %v (total %d bytes) returned %d bytes", f, op.frs(), op.total, c.Result)
				apl.err = linuxerr.EIO
				apl.mu.Unlock()
				return
			}
			haveWaiters := false
			for _, fr := range op.frs() {
				// All pages in fr have been started and were split around fr
				// when they were started (above), and apl.unloaded never
				// merges started segments. Thus, we don't need to split around
				// fr again, and fr.Intersect(ulseg.Range()) == ulseg.Range().
				for ulseg := apl.unloaded.FindSegment(fr.Start); ulseg.Ok() && ulseg.Start() < fr.End; ulseg = apl.unloaded.Remove(ulseg).NextSegment() {
					ul := ulseg.ValuePtr()
					ullen := ulseg.Range().Length()
					loadedBytes += ullen
					if !ul.started {
						panic(fmt.Sprintf("completion of %v includes pages %v that were never started", fr, ulseg.Range()))
					}
					for _, w := range ul.waiters {
						haveWaiters = true
						w.pending -= ullen
						if w.pending == 0 {
							wakeups = append(wakeups, w)
						}
					}
				}
			}
			if logAwaitedLoads && haveWaiters {
				log.Infof("MemoryFile(%p): awaited opid %d complete, read %d bytes: %v", g.f, c.ID, op.total, op.frs())
			}
		}
		// Keep apl.minUnloaded up to date. We can only determine this
		// accurately if insertions into apl.unloaded are complete.
		if g.lfStatus.Pending()&aplLFDone != 0 {
			if apl.unloaded.IsEmpty() {
				apl.minUnloaded.Store(math.MaxUint64)
			} else {
				apl.minUnloaded.Store(apl.unloaded.FirstSegment().Start())
			}
		}
		apl.mu.Unlock()
		for _, w := range wakeups {
			w.wakeup.Notify(1)
		}
		wakeups = wakeups[:0]
		dropDelayedDecRefs()
	}
}

// Preconditions:
// - All pages in fr must be becoming waste pages.
// - fr must be page-aligned.
func (apl *aplShared) cancelWasteLoad(fr memmap.FileRange) {
	// Lockless fast path:
	if fr.End <= apl.minUnloaded.Load() {
		return
	}

	apl.mu.Lock()
	defer apl.mu.Unlock()
	apl.unloaded.RemoveRangeWith(fr, func(ulseg aplUnloadedIterator) {
		ul := ulseg.ValuePtr()
		if ul.started {
			// This shouldn't be possible since page references are held while
			// reading (see MemoryFile.asyncPageLoadMain()).
			panic(fmt.Sprintf("pages %v becoming waste during inflight read from async loading", ulseg.Range()))
		}
		if n := len(ul.waiters); n != 0 {
			// This shouldn't be possible since the waiters should hold page
			// references.
			panic(fmt.Sprintf("pages %v becoming waste with %d async load waiters", ulseg.Range(), n))
		}
	})
}

type aplUnloadedSetFunctions struct{}

func (aplUnloadedSetFunctions) MinKey() uint64 {
	return 0
}

func (aplUnloadedSetFunctions) MaxKey() uint64 {
	return math.MaxUint64
}

func (aplUnloadedSetFunctions) ClearValue(ul *aplUnloadedInfo) {
	ul.waiters = nil
}

func (aplUnloadedSetFunctions) Merge(fr1 memmap.FileRange, ul1 aplUnloadedInfo, fr2 memmap.FileRange, ul2 aplUnloadedInfo) (aplUnloadedInfo, bool) {
	if ul1.off+fr1.Length() != ul2.off {
		return aplUnloadedInfo{}, false
	}
	if ul1.started || ul2.started || len(ul1.waiters) != 0 || len(ul2.waiters) != 0 {
		// Merging would be counterproductive, since we expect that these
		// segments will shortly be removed (separately) based on AIO
		// completions, which would just necessitate splitting again.
		return aplUnloadedInfo{}, false
	}
	return ul1, true
}

func (aplUnloadedSetFunctions) Split(fr memmap.FileRange, ul aplUnloadedInfo, splitAt uint64) (aplUnloadedInfo, aplUnloadedInfo) {
	ul2 := aplUnloadedInfo{
		off:     ul.off + (splitAt - fr.Start),
		started: ul.started,
		// Setting cap(ul2.waiters) == len(ul2.waiters) makes ul2
		// "copy-on-append", saving an allocation if ul2 is never appended-to.
		// This is safe since existing elements in ul.waiters will never be
		// mutated.
		waiters: ul.waiters[:len(ul.waiters):len(ul.waiters)],
	}
	return ul, ul2
}
