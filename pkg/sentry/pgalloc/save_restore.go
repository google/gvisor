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
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/aio"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/bitmap"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/gohacks"
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
	"gvisor.dev/gvisor/pkg/timing"
)

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
	//
	// f.updateUsageLocked() will unlock f.mu before calling our callback,
	// allowing concurrent calls to f.UpdateUsage() => f.updateUsageLocked() to
	// observe pages that we transiently commit (for comparisons to zero) or
	// leave committed (if opts.ExcludeCommittedZeroPages is true). Bump
	// f.isSaving to prevent this.
	f.isSaving++
	defer func() { f.isSaving-- }()
	timeScanStart := time.Now()
	zeroPage := make([]byte, hostarch.PageSize)
	var (
		decommitWarnOnce  sync.Once
		decommitPendingFR memmap.FileRange
		scanTotal         uint64
		committedTotal    uint64
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
	err := f.updateUsageLocked(nil, opts.ExcludeCommittedZeroPages, true /* callerIsSaveTo */, func(bs []byte, committed []byte, off uint64, wasCommitted bool) error {
		scanTotal += uint64(len(bs))
		for pgoff := 0; pgoff < len(bs); pgoff += hostarch.PageSize {
			i := pgoff / hostarch.PageSize
			pg := bs[pgoff : pgoff+hostarch.PageSize]
			if !bytes.Equal(pg, zeroPage) {
				committed[i] = 1
				committedTotal += hostarch.PageSize
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
	log.Infof("MemoryFile(%p): saving scanned %d bytes, saw %d committed bytes (ExcludeCommittedZeroPages=%v), decommitted %d bytes in %d syscalls, %s", f, scanTotal, committedTotal, opts.ExcludeCommittedZeroPages, decommitTotal, decommitCount, time.Since(timeScanStart))

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
	log.Infof("MemoryFile(%p): saved pages in %s (%d bytes, %.3f MiB/s)", f, durPages, savedBytes, float64(savedBytes)/durPages.Seconds()/(1024.0*1024.0))

	return nil
}

// LoadOpts provides options to MemoryFile.LoadFrom().
type LoadOpts struct {
	// If PagesFile is not nil, then page contents will be read from PagesFile
	// rather than from r.
	PagesFile *AsyncPagesFileLoad

	// Optional timeline for the restore process.
	// If async page loading is enabled, a forked timeline will be created, so
	// ownership of this timeline remains in the hands of the caller of
	// LoadFrom.
	Timeline *timing.Timeline
}

// LoadFrom loads MemoryFile state from the given stream.
func (f *MemoryFile) LoadFrom(ctx context.Context, r io.Reader, opts *LoadOpts) error {
	mfTimeline := opts.Timeline.Fork(fmt.Sprintf("mf:%p", f)).Lease()
	defer mfTimeline.End()
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
	mfTimeline.Reached("metadata loaded")
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
		mfTimeline.Reached("mmaped chunks")
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

	// Register this MemoryFile with async page loading if a pages file has
	// been provided.
	var amfl *asyncMemoryFileLoad
	if opts.PagesFile != nil {
		amfl = &asyncMemoryFileLoad{
			f:        f,
			pf:       opts.PagesFile,
			timeline: mfTimeline.Transfer(),
		}
		amfl.pf.amflsMu.Lock()
		if err := amfl.pf.err(); err != nil {
			amfl.pf.amflsMu.Unlock()
			return err
		}
		amfl.pf.amfls.PushBack(amfl)
		amfl.pf.amflsMu.Unlock()
		f.asyncPageLoad.Store(amfl)
		defer func() {
			amfl.pf.amflsMu.Lock()
			defer amfl.pf.amflsMu.Unlock()
			amfl.pf.mu.Lock()
			defer amfl.pf.mu.Unlock()
			amfl.lfDone = true
			if amfl.unloaded.IsEmpty() {
				// The async page loader goroutine does this when it
				// transitions amfl.unloaded from non-empty to empty with
				// amfl.lfDone == true, but since amfl.unloaded is already
				// empty (async page loading for this MemoryFile finished
				// before we got here, possibly because the MemoryFile was
				// empty), we have to do so instead.
				amfl.minUnloaded.Store(math.MaxUint64)
				amfl.pf.amfls.Remove(amfl)
				amfl.f.asyncPageLoad.Store(nil)
				amfl.timeline.End()
			}
		}()
	}

	// Load committed pages.
	wr := wire.Reader{Reader: r}
	timePagesStart := time.Now()
	loadedBytes := uint64(0)
	minUnloadedInit := false
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
		if amfl != nil {
			// Record where to read data.
			if !minUnloadedInit {
				minUnloadedInit = true
				amfl.minUnloaded.Store(maFR.Start)
			}
			amfl.pf.mu.Lock()
			amfl.unloaded.InsertRange(maFR, aplUnloadedInfo{
				off: amfl.pf.loadOff,
			})
			amfl.pf.mu.Unlock()
			amfl.pf.loadOff += amount
			amfl.pf.lfStatus.Notify(aplLFPending)
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
	if amfl != nil {
		log.Infof("MemoryFile(%p): loaded page file offsets in %s; async loading %d bytes", f, durPages, loadedBytes)
	} else {
		log.Infof("MemoryFile(%p): loaded pages in %s (%d bytes, %.3f MB/s)", f, durPages, loadedBytes, float64(loadedBytes)*1e-6/durPages.Seconds())
	}

	return nil
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

// AsyncPagesFileLoad holds async page loading state for a single pages file.
type AsyncPagesFileLoad struct {
	// loadOff is the offset in the pages file from which the next page should
	// be loaded. loadOff is not synchronized since it is only accessed by
	// MemoryFile.LoadFrom(), which cannot be called concurrently using the
	// same AsyncPagesFileLoad.
	loadOff uint64

	mu apflMutex

	// If errVal is not nil, it is an error that has terminated asynchronous
	// page loading. errVal can only be set by the async page loader goroutine,
	// and can only transition from nil to non-nil once, after which it is
	// immutable. errVal is stored with mu locked.
	errVal atomic.Value

	// priority contains possibly-unstarted ranges with at least one waiter.
	// priority is protected by mu.
	priority ringdeque.Deque[aplFileRange]

	// Padding before state used mostly by the async page loader goroutine:
	_ [hostarch.CacheLineSize]byte

	// amfls tracks MemoryFiles that are currently loading from the pages file.
	// amfls is protected by amflsMu.
	amflsMu amflsMutex
	amfls   asyncMemoryFileLoadList

	// lfStatus communicates MemoryFile.LoadFrom() state to the async page
	// loader goroutine.
	lfStatus syncevent.Waiter

	// numWaiters is the current number of waiting waiters. numWaiters is
	// protected by mu.
	numWaiters int

	// totalWaiters is the number of waiters that have ever waited for pages
	// from this pages file. totalWaiters is protected by mu.
	totalWaiters int

	// timeStartWaiters was the value of gohacks.Nanotime() when numWaiters
	// most recently transitioned from 0 to 1. If numWaiters is 0,
	// timeStartWaiters is MaxInt64. timeStartWaiters is protected by mu.
	timeStartWaiters int64

	// nsWaitedOne is the duration for which at least one waiter was waiting
	// for a load. nsWaitedTotal is the duration for which waiters were waiting
	// for loads, summed across all waiters. bytesWaited is the number of bytes
	// for which at least one waiter waited. These fields are protected by mu.
	durWaitedOne   time.Duration
	durWaitedTotal time.Duration
	bytesWaited    uint64

	// bytesLoaded is the number of bytes that have been loaded so far.
	// bytesLoaded is protected by mu.
	bytesLoaded uint64

	// Following fields are exclusive to the async page loader goroutine.

	timeline     *timing.Timeline // immutable
	doneCallback func(error)      // immutable

	// q issues reads to the pages file. GoQueue is faster than LinuxQueue here
	// since it can allocate and zero MemoryFile pages in parallel. q is
	// immutable.
	q *aio.GoQueue

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

// Possible events in AsyncPagesFileLoad.lfStatus:
const (
	aplLFPending syncevent.Set = 1 << iota
	aplLFDone
)

type aplFileRange struct {
	amfl *asyncMemoryFileLoad
	memmap.FileRange
}

func (apfl *AsyncPagesFileLoad) err() error {
	if v := apfl.errVal.Load(); v != nil {
		return v.(error)
	}
	return nil
}

// asyncMemoryFileLoad holds async page loading state for a single MemoryFile.
type asyncMemoryFileLoad struct {
	f        *MemoryFile         // immutable
	pf       *AsyncPagesFileLoad // immutable
	timeline *timing.Timeline    // immutable

	// minUnloaded is the MemoryFile offset of the first unloaded byte.
	minUnloaded atomicbitops.Uint64

	// unloaded tracks pages in the MemoryFile that have not been loaded.
	// unloaded is protected by pf.mu.
	unloaded aplUnloadedSet

	// lfDone is true if MemoryFile.LoadFrom() has finished inserting into
	// unloaded. lfDone is protected by pf.mu.
	lfDone bool

	// asyncMemoryFileLoadEntry links into pf.amfls. asyncMemoryFileLoadEntry
	// is protected by pf.amflsMu.
	asyncMemoryFileLoadEntry

	// Padding before state exclusive to the async page loader goroutine:
	_ [hostarch.CacheLineSize]byte

	// minUnstarted is the lowest offset that may map to a segment in unloaded
	// for which aplUnloadedInfo.started == false.
	minUnstarted uint64
}

// aplUnloadedInfo is the value type of asyncMemoryFileLoad.unloaded.
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
	// pages in fr are loaded. wakeup is internally synchronized. fr is
	// immutable after initialization.
	wakeup syncevent.Waiter
	fr     memmap.FileRange

	// timeStart was the value of gohacks.Nanotime() when this waiter started
	// waiting. timeStart is immutable after initialization.
	timeStart int64

	// pending is the number of unloaded bytes that this waiter is waiting for.
	// pending is protected by aplShared.mu.
	pending uint64
}

var aplWaiterPool = sync.Pool{
	New: func() any {
		var w aplWaiter
		w.wakeup.Init()
		return &w
	},
}

// aplOp tracks async page load state corresponding to a single AIO read
// operation.
type aplOp struct {
	// total is the number of bytes to be read by the operation.
	total uint64

	// end is the pages file offset at which the read ends.
	end uint64

	// amfl represents the MemoryFile being loaded.
	amfl *asyncMemoryFileLoad

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

// StartAsyncPagesFileLoad constructs asynchronous loading state for the pages
// file with host file descriptor pagesFD. It does not take ownership of
// pagesFD, which must remain valid until doneCallback is invoked.
func StartAsyncPagesFileLoad(pagesFD int32, doneCallback func(error), timeline *timing.Timeline) *AsyncPagesFileLoad {
	apfl := &AsyncPagesFileLoad{
		timeline:     timeline.Fork("async page loading"),
		doneCallback: doneCallback,
		q:            aio.NewGoQueue(aplQueueCapacity),
		qavail:       aplQueueCapacity,
		fd:           pagesFD,
		opsBusy:      bitmap.New(aplQueueCapacity),
	}
	// Mark ops in opsBusy that don't actually exist as permanently busy.
	for i, n := aplQueueCapacity, apfl.opsBusy.Size(); i < n; i++ {
		apfl.opsBusy.Add(uint32(i))
	}
	apfl.lfStatus.Init()
	go apfl.main()
	return apfl
}

// MemoryFilesDone must be called after calling LoadFrom() for all MemoryFiles
// loading from apfl.
func (apfl *AsyncPagesFileLoad) MemoryFilesDone() {
	apfl.lfStatus.Notify(aplLFDone)
}

// IsAsyncLoading returns true if async page loading is in progress or has
// failed permanently.
func (f *MemoryFile) IsAsyncLoading() bool {
	return f.asyncPageLoad.Load() != nil
}

// AwaitLoadAll blocks until async page loading has completed. If async page
// loading is not in progress, AwaitLoadAll returns immediately.
func (f *MemoryFile) AwaitLoadAll() error {
	if amfl := f.asyncPageLoad.Load(); amfl != nil {
		return amfl.awaitLoad(memmap.FileRange{0, hostarch.PageRoundDown(uint64(math.MaxUint64))})
	}
	return nil
}

// awaitLoad blocks until data has been loaded for all pages in fr.
//
// Preconditions: At least one reference must be held on all unloaded pages in
// fr.
func (amfl *asyncMemoryFileLoad) awaitLoad(fr memmap.FileRange) error {
	// Lockless fast path:
	if fr.End <= amfl.minUnloaded.Load() {
		return nil
	}

	// fr might not be page-aligned; everything else involved in async page
	// loading requires page-aligned FileRanges.
	fr.Start = hostarch.PageRoundDown(fr.Start)
	fr.End = hostarch.MustPageRoundUp(fr.End)

	apfl := amfl.pf
	apfl.mu.Lock()
	if err := apfl.err(); err != nil {
		if amfl.unloaded.IsEmptyRange(fr) {
			// fr is already loaded.
			apfl.mu.Unlock()
			return nil
		}
		// A previous error means that fr will never be loaded.
		apfl.mu.Unlock()
		return err
	}
	w := aplWaiterPool.Get().(*aplWaiter)
	defer aplWaiterPool.Put(w)
	w.fr = fr
	w.pending = 0
	amfl.unloaded.MutateRange(fr, func(ulseg aplUnloadedIterator) bool {
		ul := ulseg.ValuePtr()
		ulFR := ulseg.Range()
		ullen := ulFR.Length()
		if len(ul.waiters) == 0 {
			apfl.bytesWaited += ullen
			if !ul.started {
				apfl.priority.PushBack(aplFileRange{amfl, ulFR})
			}
			if logAwaitedLoads {
				log.Infof("MemoryFile(%p): prioritize %v", amfl.f, ulFR)
			}
		}
		ul.waiters = append(ul.waiters, w)
		w.pending += ullen
		return true
	})
	pending := w.pending != 0
	if pending {
		w.timeStart = gohacks.Nanotime()
		if apfl.numWaiters == 0 {
			apfl.timeStartWaiters = w.timeStart
		}
		apfl.numWaiters++
		apfl.totalWaiters++
	}
	apfl.mu.Unlock()
	if pending {
		if logAwaitedLoads {
			log.Infof("MemoryFile(%p): awaitLoad goid %d start: %v (%d bytes)", amfl.f, goid.Get(), fr, fr.Length())
		}
		w.wakeup.WaitAndAckAll()
		if logAwaitedLoads {
			waitNS := gohacks.Nanotime() - w.timeStart
			log.Infof("MemoryFile(%p): awaitLoad goid %d waited %v: %v (%d bytes)", amfl.f, goid.Get(), time.Duration(waitNS), fr, fr.Length())
		}
	}
	return apfl.err()
}

func (apfl *AsyncPagesFileLoad) canEnqueue() bool {
	return apfl.qavail > 0
}

// Preconditions: apfl.canEnqueue() == true.
func (apfl *AsyncPagesFileLoad) enqueueCurOp() {
	if apfl.qavail <= 0 {
		panic("queue full")
	}
	op := apfl.curOp
	if op.total == 0 {
		panic("invalid read of 0 bytes")
	}
	if op.total > aplReadMaxBytes {
		panic(fmt.Sprintf("read of %d bytes exceeds per-read limit of %d bytes", op.total, aplReadMaxBytes))
	}

	apfl.qavail--
	apfl.curOp = nil
	if op.iovecsLen == 1 {
		// Perform a non-vectorized read to save an indirection (and
		// userspace-to-kernelspace copy) in the aio.Queue implementation.
		aio.Read(apfl.q, uint64(apfl.curOpID), apfl.fd, op.off(), sliceFromIovec(op.iovecsData[0]))
	} else {
		aio.Readv(apfl.q, uint64(apfl.curOpID), apfl.fd, op.off(), op.iovecs())
	}
	if logAwaitedLoads && !op.tempRef {
		log.Infof("MemoryFile(%p): awaited opid %d start, read %d bytes: %v", op.amfl.f, apfl.curOpID, op.total, op.frs())
	}
}

// Preconditions:
// - apfl.canEnqueue() == true.
// - fr.Length() > 0.
// - fr must be page-aligned.
func (apfl *AsyncPagesFileLoad) enqueueRange(amfl *asyncMemoryFileLoad, fr memmap.FileRange, off uint64, tempRef bool) uint64 {
	for {
		if apfl.curOp == nil {
			id, err := apfl.opsBusy.FirstZero(0)
			if err != nil {
				panic(fmt.Sprintf("all ops busy with qavail=%d: %v", apfl.qavail, err))
			}
			apfl.opsBusy.Add(id)
			op := &apfl.ops[id]
			op.total = 0
			op.frsLen = 0
			op.iovecsLen = 0
			apfl.curOp = op
			apfl.curOpID = id
		}
		n := apfl.combine(amfl, fr, off, tempRef)
		if n > 0 {
			return n
		}
		// Flush the existing (conflicting) op and try again with a new one.
		apfl.enqueueCurOp()
		if !apfl.canEnqueue() {
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
func (apfl *AsyncPagesFileLoad) combine(amfl *asyncMemoryFileLoad, fr memmap.FileRange, off uint64, tempRef bool) uint64 {
	op := apfl.curOp
	if op.total != 0 {
		if op.end != off {
			// Non-contiguous in the pages file.
			return 0
		}
		if op.amfl != amfl {
			// Differing MemoryFile. We could handle this by making the
			// asyncMemoryFileLoad per-FileRange, but this would bloat aplOp
			// and should happen very infrequently.
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
	amfl.f.forEachMappingSlice(fr, func(bs []byte) {
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
		op.amfl = amfl
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

func (apfl *AsyncPagesFileLoad) main() {
	q := apfl.q
	defer func() {
		// Destroy q first since this synchronously stops inflight I/O.
		q.Destroy()
		apfl.timeline.End()
		// Wake up any remaining waiters so that they can observe apfl.err().
		// Leave all segments in asyncMemoryFileLoad.unloaded so that new
		// callers of awaitLoad() will still observe the correct (permanently
		// unloaded) segments.
		apfl.amflsMu.Lock()
		apfl.mu.Lock()
		for amfl := apfl.amfls.Front(); amfl != nil; amfl = amfl.Next() {
			for ulseg := amfl.unloaded.FirstSegment(); ulseg.Ok(); ulseg = ulseg.NextSegment() {
				ul := ulseg.ValuePtr()
				ullen := ulseg.Range().Length()
				for _, w := range ul.waiters {
					w.pending -= ullen
					if w.pending == 0 {
						w.wakeup.Notify(1)
					}
				}
				ul.started = false
				ul.waiters = nil
			}
		}
		apfl.mu.Unlock()
		apfl.amflsMu.Unlock()
		if apfl.doneCallback != nil {
			apfl.doneCallback(apfl.err())
		}
	}()

	// Storage reused between main loop iterations:
	var completions []aio.Completion
	var wakeups []*aplWaiter
	var decRefs []aplFileRange

	dropDelayedDecRefs := func() {
		if len(decRefs) != 0 {
			for _, fr := range decRefs {
				fr.amfl.f.DecRef(fr.FileRange)
			}
			decRefs = decRefs[:0]
		}
	}
	defer dropDelayedDecRefs()

	// Don't start timing until we have pages to load.
	apfl.lfStatus.Wait()
	timeStart := gohacks.Nanotime()
	apfl.timeline.Reached("async page loading started")
	if log.IsLogging(log.Debug) {
		log.Debugf("Async page loading started")
		progressTicker := time.NewTicker(5 * time.Second)
		progressStopC := make(chan struct{})
		defer func() { close(progressStopC) }()
		go func() {
			timeLast := timeStart
			bytesLoadedLast := uint64(0)
			for {
				select {
				case <-progressStopC:
					progressTicker.Stop()
					return
				case <-progressTicker.C:
					// Take a snapshot of our progress.
					apfl.mu.Lock()
					totalWaiters := apfl.totalWaiters
					timeStartWaiters := apfl.timeStartWaiters
					durWaitedOne := apfl.durWaitedOne
					durWaitedTotal := apfl.durWaitedTotal
					bytesWaited := apfl.bytesWaited
					bytesLoaded := apfl.bytesLoaded
					apfl.mu.Unlock()
					now := gohacks.Nanotime()
					durTotal := time.Duration(now - timeStart)
					// apfl can have at least one waiter for a very long time
					// due to new waiters enqueueing before old ones are
					// served; avoid apparent jumps in durWaitedOne.
					if timeStartWaiters < now {
						durWaitedOne += time.Duration(now - timeStartWaiters)
					}
					durDelta := time.Duration(now - timeLast)
					bytesLoadedDelta := bytesLoaded - bytesLoadedLast
					bandwidthSinceLast := float64(bytesLoadedDelta) * 1e-6 / durDelta.Seconds()
					apfl.timeline.Reached(fmt.Sprintf("%.3f MB/s", bandwidthSinceLast))
					log.Infof("Async page loading in progress for %s (%d bytes, %.3f MB/s); since last update %s ago: %d bytes, %.3f MB/s; %d waiters waited %v~%v for %d bytes", durTotal.Round(time.Millisecond), bytesLoaded, float64(bytesLoaded)*1e-6/durTotal.Seconds(), durDelta.Round(time.Millisecond), bytesLoadedDelta, bandwidthSinceLast, totalWaiters, durWaitedOne.Round(time.Millisecond), durWaitedTotal.Round(time.Millisecond), bytesWaited)
					timeLast = now
					bytesLoadedLast = bytesLoaded
				}
			}
		}()
	}

	for {
		// Enqueue as many reads as possible.
		if !apfl.canEnqueue() {
			panic("main loop invariant failed")
		}
		// Prioritize reading pages with waiters.
		apfl.mu.Lock()
		for apfl.canEnqueue() && !apfl.priority.Empty() {
			fr := apfl.priority.PopFront()
			// All pages in apfl.priority have non-zero waiters and were split
			// around fr by fr.amfl.awaitLoad(), and fr.amfl.unloaded never
			// merges segments with waiters. Thus, we don't need to split
			// around fr again, and fr.Intersect(ulseg.Range()) ==
			// ulseg.Range().
			ulseg := fr.amfl.unloaded.LowerBoundSegment(fr.Start)
			for ulseg.Ok() && ulseg.Start() < fr.End {
				ul := ulseg.ValuePtr()
				ulFR := ulseg.Range()
				if ul.started {
					fr.Start = ulFR.End
					ulseg = ulseg.NextSegment()
					continue
				}
				// Awaited pages are guaranteed to have a reference held (by
				// fr.amfl.awaitLoad() precondition), so they can't become
				// waste (which would allow them to be racily released or
				// recycled).
				n := apfl.enqueueRange(fr.amfl, ulFR, ul.off, false /* tempRef */)
				if n == 0 {
					// Try again in the next iteration of the main loop, when
					// we have space in the queue again.
					apfl.priority.PushFront(fr)
					break
				}
				ulFR.End = ulFR.Start + n
				ulseg = fr.amfl.unloaded.SplitAfter(ulseg, ulFR.End)
				ulseg.ValuePtr().started = true
				fr.Start = ulFR.End
				if fr.Length() > 0 {
					// Cycle the rest of fr to the end of apl.priority. This
					// prevents large awaited reads from starving other
					// waiters.
					apfl.priority.PushBack(fr)
					break
				}
				ulseg = ulseg.NextSegment()
			}
		}
		apfl.mu.Unlock()
		// Fill remaining queue with reads for pages with no waiters.
		if apfl.canEnqueue() {
			apfl.amflsMu.Lock()
			// Unawaited loads from earlier MemoryFiles are prioritized over
			// unawaited loads from later MemoryFiles. Callers of
			// MemoryFile.LoadFrom() (in //pkg/sentry/kernel) always load the
			// MemoryFile containing application memory before other
			// MemoryFiles (which most often store disk state); thus, this
			// property ensures that application memory is prioritized over
			// disk state. This is reasonable since memory latency is
			// significantly lower than disk latency, so applications are
			// likely to be more sensitive to elevated memory latency due to
			// awaited loads vs. elevated disk latency.
		amflsLoop:
			for amfl := apfl.amfls.Front(); amfl != nil; amfl = amfl.Next() {
				amfl.f.mu.Lock()
				apfl.mu.Lock()
				ulseg := amfl.unloaded.LowerBoundSegment(amfl.minUnstarted)
				for ulseg.Ok() {
					ul := ulseg.ValuePtr()
					ulFR := ulseg.Range()
					if ul.started {
						amfl.minUnstarted = ulFR.End
						ulseg = ulseg.NextSegment()
						continue
					}
					// We need to take page references during reading to
					// prevent pages from becoming waste due to concurrent
					// dropping of the last reference.
					n := apfl.enqueueRange(amfl, ulFR, ul.off, true /* tempRef */)
					if n == 0 {
						apfl.mu.Unlock()
						amfl.f.mu.Unlock()
						break amflsLoop
					}
					ulFR.End = ulFR.Start + n
					ulseg = amfl.unloaded.SplitAfter(ulseg, ulFR.End)
					ulseg.ValuePtr().started = true
					amfl.minUnstarted = ulFR.End
					amfl.f.incRefLocked(ulFR)
					if !apfl.canEnqueue() {
						apfl.mu.Unlock()
						amfl.f.mu.Unlock()
						break amflsLoop
					}
					ulseg = ulseg.NextSegment()
				}
				apfl.mu.Unlock()
				amfl.f.mu.Unlock()
			}
			apfl.amflsMu.Unlock()
		}
		// Flush pending op.
		if apfl.curOp != nil {
			apfl.enqueueCurOp()
		}

		if apfl.qavail == aplQueueCapacity {
			// We are out of work to do.
			ev := apfl.lfStatus.Wait()
			if ev&aplLFPending != 0 {
				// We may have raced with MemoryFile.LoadFrom() inserting into
				// asyncMemoryFileLoad.unloaded.
				apfl.lfStatus.Ack(aplLFPending)
				continue
			}
			if ev&aplLFDone != 0 {
				// Successfully completed all loading for all MemoryFiles.
				durTotal := time.Duration(gohacks.Nanotime() - timeStart)
				apfl.mu.Lock()
				log.Infof("Async page loading completed in %s (%d bytes, %.3f MB/s); %d waiters waited %v~%v for %d bytes", durTotal.Round(time.Millisecond), apfl.bytesLoaded, float64(apfl.bytesLoaded)*1e-6/durTotal.Seconds(), apfl.totalWaiters, apfl.durWaitedOne.Round(time.Millisecond), apfl.durWaitedTotal.Round(time.Millisecond), apfl.bytesWaited)
				apfl.mu.Unlock()
				return
			}
			panic(fmt.Sprintf("unknown events in lfStatus: %#x", ev))
		}

		// Wait for any number of reads to complete.
		var err error
		completions, err = q.Wait(completions[:0], 1 /* minCompletions */)
		if err != nil {
			log.Warningf("Async page loading failed: aio.Queue.Wait failed: %v", err)
			apfl.mu.Lock()
			apfl.errVal.Store(linuxerr.EIO)
			apfl.mu.Unlock()
			return
		}

		// Process completions.
		apfl.amflsMu.Lock()
		apfl.mu.Lock()
		for _, c := range completions {
			op := &apfl.ops[c.ID]
			apfl.opsBusy.Remove(uint32(c.ID))
			apfl.qavail++
			if op.tempRef {
				// Delay f.DecRef(fr) until after dropping locks. This is
				// required to avoid lock recursion via dropping the last
				// reference => asyncMemoryFileLoad.cancelWasteLoad() =>
				// apfl.mu.Lock().
				for _, fr := range op.frs() {
					decRefs = append(decRefs, aplFileRange{op.amfl, fr})
				}
			}
			if err := c.Err(); err != nil {
				log.Warningf("Async page loading failed: read for MemoryFile(%p) pages %v failed: %v", op.amfl.f, op.frs(), err)
				apfl.errVal.Store(err)
				apfl.mu.Unlock()
				apfl.amflsMu.Unlock()
				return
			}
			if uint64(c.Result) != op.total {
				// TODO: Is this something we actually have to worry about? If
				// so, we need to reissue the remainder of the read...
				log.Warningf("Async page loading failed: read for MemoryFile(%p) pages %v (total %d bytes) returned %d bytes", op.amfl.f, op.frs(), op.total, c.Result)
				apfl.errVal.Store(linuxerr.EIO)
				apfl.mu.Unlock()
				apfl.amflsMu.Unlock()
				return
			}
			apfl.bytesLoaded += op.total
			amfl := op.amfl
			haveWaiters := false
			now := int64(0)
			for _, fr := range op.frs() {
				// All pages in fr have been started and were split around fr
				// when they were started (above), and fr.amfl.unloaded never
				// merges started segments. Thus, we don't need to split around
				// fr again, and fr.Intersect(ulseg.Range()) == ulseg.Range().
				for ulseg := amfl.unloaded.FindSegment(fr.Start); ulseg.Ok() && ulseg.Start() < fr.End; ulseg = amfl.unloaded.Remove(ulseg).NextSegment() {
					ul := ulseg.ValuePtr()
					ullen := ulseg.Range().Length()
					if !ul.started {
						panic(fmt.Sprintf("MemoryFile(%p): completion of %v includes pages %v that were never started", amfl.f, fr, ulseg.Range()))
					}
					for _, w := range ul.waiters {
						haveWaiters = true
						w.pending -= ullen
						if w.pending == 0 {
							wakeups = append(wakeups, w)
							if now == 0 {
								now = gohacks.Nanotime()
							}
							// This definition of "wait time" skips the time
							// taken for w to wake up (bad), but avoids having
							// to lock apfl.mu again in apfl.awaitLoad()
							// (good).
							apfl.durWaitedTotal += time.Duration(now - w.timeStart)
							apfl.numWaiters--
							if apfl.numWaiters == 0 {
								apfl.durWaitedOne += time.Duration(now - apfl.timeStartWaiters)
								apfl.timeStartWaiters = math.MaxInt64
							}
						}
					}
				}
			}
			if logAwaitedLoads && haveWaiters {
				log.Infof("MemoryFile(%p): awaited opid %d complete, read %d bytes: %v", op.amfl.f, c.ID, op.total, op.frs())
			}
			// Keep amfl.minUnloaded up to date. We can only determine this
			// accurately if insertions into amfl.unloaded are complete.
			if amfl.lfDone {
				if amfl.unloaded.IsEmpty() {
					amfl.minUnloaded.Store(math.MaxUint64)
					apfl.amfls.Remove(amfl)
					amfl.f.asyncPageLoad.Store(nil)
					amfl.timeline.End()
				} else {
					amfl.minUnloaded.Store(amfl.unloaded.FirstSegment().Start())
				}
			}
		}
		apfl.mu.Unlock()
		apfl.amflsMu.Unlock()
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
func (amfl *asyncMemoryFileLoad) cancelWasteLoad(fr memmap.FileRange) {
	// Lockless fast path:
	if fr.End <= amfl.minUnloaded.Load() {
		return
	}

	amfl.pf.mu.Lock()
	defer amfl.pf.mu.Unlock()
	amfl.unloaded.RemoveRangeWith(fr, func(ulseg aplUnloadedIterator) {
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
