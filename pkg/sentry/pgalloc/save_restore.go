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
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/bitmap"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/gohacks"
	"gvisor.dev/gvisor/pkg/goid"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/ringdeque"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/state/stateio"
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
	// If PagesFile is not nil, then page contents will be written to PagesFile
	// rather than to w.
	PagesFile *AsyncPagesFileSave

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
func (f *MemoryFile) SaveTo(ctx context.Context, w io.Writer, opts *SaveOpts) error {
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

	// Register this MemoryFile with async page saving if a pages file has been
	// provided.
	var amfs *asyncMemoryFileSave
	if opts.PagesFile != nil {
		var sf stateio.SourceFile
		if opts.PagesFile.aw.NeedRegisterSourceFD() {
			fileSize := uint64(len(f.chunksLoad())) * chunkSize
			var err error
			sf, err = opts.PagesFile.aw.RegisterSourceFD(int32(f.file.Fd()), fileSize, f.getClientFileRangeSettings(fileSize))
			if err != nil {
				return fmt.Errorf("failed to register MemoryFile with pages file: %w", err)
			}
		}
		amfs = &asyncMemoryFileSave{
			f:  f,
			pf: opts.PagesFile,
			sf: sf,
		}
	}

	// Save committed pages.
	ww := wire.Writer{Writer: w}
	timePagesStart := time.Now()
	bytesSaved := uint64(0)
	for maseg := f.memAcct.FirstSegment(); maseg.Ok(); maseg = maseg.NextSegment() {
		if !maseg.ValuePtr().knownCommitted {
			continue
		}
		maFR := maseg.Range()
		amount := maFR.Length()
		if amfs != nil {
			// Record data to be written.
			amfs.pf.mu.Lock()
			amfs.pf.unsaved.PushBack(apsRange{
				amfs:      amfs,
				FileRange: maFR,
			})
			amfs.pf.saveOff += amount
			amfs.pf.mu.Unlock()
			amfs.pf.stStatus.Notify(apsSTPending)
		} else {
			// Write a header to distinguish from objects.
			if err := state.WriteHeader(&ww, amount, false); err != nil {
				return err
			}
			// Write out data.
			var ioErr error
			f.forEachMappingSlice(maFR, func(s []byte) {
				if ioErr != nil {
					return
				}
				_, ioErr = w.Write(s)
			})
			if ioErr != nil {
				return ioErr
			}
		}
		bytesSaved += amount
	}
	durPages := time.Since(timePagesStart)
	if amfs != nil {
		log.Infof("MemoryFile(%p): saved page file offsets in %s; async saving %d bytes", f, durPages, bytesSaved)
	} else {
		log.Infof("MemoryFile(%p): saved pages in %s (%d bytes, %.3f MB/s)", f, durPages, bytesSaved, float64(bytesSaved)*1e-6/durPages.Seconds())
	}

	return nil
}

// AsyncPagesFileSave holds async page saving state for a single pages file.
type AsyncPagesFileSave struct {
	mu apfsMutex

	// saveOff is the offset in the pages file at which the next page to be
	// inserted into unsaved will be saved. saveOff is protected by mu.
	saveOff uint64

	// unsaved tracks pages that have not been saved. unsaved is protected by mu.
	unsaved ringdeque.Deque[apsRange]

	// stStatus communicates state from MemoryFile.SaveTo() and its callers to
	// the goroutine.
	stStatus syncevent.Waiter

	// Padding before fields exclusive to the async page saver goroutine:
	_ [hostarch.CacheLineSize]byte

	doneCallback func(error) // immutable

	// aw is the pages file. aw is immutable.
	aw stateio.AsyncWriter

	// maxWriteBytes is hostarch.PageRoundDown(ar.MaxWriteBytes()), cached to
	// avoid interface method calls and recomputation. maxWriteBytes is
	// immutable.
	maxWriteBytes uint64

	// qavail is unused capacity in aw.
	qavail int

	// Pages file writes are always contiguous, even when the corresponding
	// memmap.FileRanges and mappings are not. If curOp is not nil, it is the
	// current apsOp under construction, and curOpID is its index into ops.
	curOp   *apsOp
	curOpID uint32

	// opsBusy tracks which apsOps in ops are in use (correspond to
	// inflight operations or curOp).
	opsBusy bitmap.Bitmap

	// ops stores all apsOps.
	ops []apsOp

	// If err is not nil, it is the error that has terminated async page
	// saving. Note that unlike AsyncPagesFileLoad.err(),
	// AsyncPagesFileSave.err is never returned to application syscalls and
	// hence is not constrained to being an errno.
	err error
}

// Possible events in AsyncPagesFileSave.stStatus:
const (
	apsSTPending syncevent.Set = 1 << iota
	apsSTDone
)

// asyncMemoryFileSave holds state for async page saving from a single
// MemoryFile.
type asyncMemoryFileSave struct {
	// Immutable fields:
	f  *MemoryFile
	pf *AsyncPagesFileSave
	sf stateio.SourceFile
}

type apsRange struct {
	amfs *asyncMemoryFileSave
	memmap.FileRange
}

// apsOp tracks async page save state corresponding to a single AIO write
// operation.
type apsOp struct {
	// total is the number of bytes to be written by the operation.
	total uint64

	// amfs represents the MemoryFile being saved.
	amfs *asyncMemoryFileSave

	// frs are the MemoryFile ranges being saved.
	frs []memmap.FileRange

	// iovecs contains mappings of frs.
	iovecs []unix.Iovec
}

// StartAsyncPagesFileSave constructs asynchronous saving state for the pages
// file aw. It takes ownership of aw, even if it returns a non-nil error.
func StartAsyncPagesFileSave(aw stateio.AsyncWriter, doneCallback func(error)) (*AsyncPagesFileSave, error) {
	maxWriteBytes := hostarch.PageRoundDown(aw.MaxWriteBytes())
	if maxWriteBytes <= 0 {
		aw.Close()
		return nil, fmt.Errorf("stateio.AsyncWriter.MaxWriteBytes() (%d) must be at least one page)", aw.MaxWriteBytes())
	}
	// Cap maxParallel due to the uint32 range of bitmap.Bitmap.
	maxParallel := min(aw.MaxParallel(), 1<<30)
	apfs := &AsyncPagesFileSave{
		doneCallback:  doneCallback,
		aw:            aw,
		maxWriteBytes: maxWriteBytes,
		qavail:        maxParallel,
		opsBusy:       bitmap.New(uint32(maxParallel)),
		ops:           make([]apsOp, maxParallel),
	}
	// Mark ops in opsBusy that don't actually exist as permanently busy.
	for i, n := maxParallel, apfs.opsBusy.Size(); i < n; i++ {
		apfs.opsBusy.Add(uint32(i))
	}
	// Pre-allocate slices in ops.
	maxRanges := aw.MaxRanges()
	for i := range apfs.ops {
		op := &apfs.ops[i]
		op.frs = make([]memmap.FileRange, 0, maxRanges)
		op.iovecs = make([]unix.Iovec, 0, maxRanges)
	}
	apfs.stStatus.Init()
	go apfs.main()
	return apfs, nil
}

// MemoryFilesDone must be called after calling SaveTo() for all MemoryFiles
// saving to apfs. MemoryFilesDone may be called multiple times; subsequent
// calls have no effect.
func (apfs *AsyncPagesFileSave) MemoryFilesDone() {
	apfs.stStatus.Notify(apsSTDone)
}

func (apfs *AsyncPagesFileSave) canEnqueue() bool {
	return apfs.qavail > 0
}

// Preconditions: apfs.canEnqueue() == true.
func (apfs *AsyncPagesFileSave) enqueueCurOp() {
	if apfs.qavail <= 0 {
		panic("queue full")
	}
	op := apfs.curOp
	if op.total == 0 {
		panic("invalid write of 0 bytes")
	}
	if op.total > apfs.maxWriteBytes {
		panic(fmt.Sprintf("write of %d bytes exceeds per-write limit of %d bytes", op.total, apfs.maxWriteBytes))
	}

	apfs.qavail--
	apfs.curOp = nil
	if len(op.frs) == 1 && len(op.iovecs) == 1 {
		// Perform a non-vectorized write to save an indirection (and possible
		// userspace-to-kernelspace copy) in the AsyncWriter implementation.
		apfs.aw.AddWrite(int(apfs.curOpID), op.amfs.sf, op.frs[0], stateio.SliceFromIovec(op.iovecs[0]))
	} else {
		apfs.aw.AddWritev(int(apfs.curOpID), op.total, op.amfs.sf, op.frs, op.iovecs)
	}
}

// Preconditions:
// - apfs.canEnqueue() == true.
// - mfr.Length() > 0.
// - mfr must be page-aligned.
func (apfs *AsyncPagesFileSave) enqueueRange(mfr apsRange) uint64 {
	for {
		if apfs.curOp == nil {
			id, err := apfs.opsBusy.FirstZero(0)
			if err != nil {
				panic(fmt.Sprintf("all ops busy with qavail=%d: %v", apfs.qavail, err))
			}
			apfs.opsBusy.Add(id)
			op := &apfs.ops[id]
			op.total = 0
			op.frs = op.frs[:0]
			op.iovecs = op.iovecs[:0]
			apfs.curOp = op
			apfs.curOpID = id
		}
		n := apfs.combine(mfr)
		if n > 0 {
			return n
		}
		// Flush the existing (conflicting) op and try again with a new one.
		apfs.enqueueCurOp()
		if !apfs.canEnqueue() {
			return 0
		}
	}
}

// combine adds as much of the given save as possible to apfs.curOp and returns
// the number of bytes added.
//
// Preconditions:
// - mfr.Length() > 0.
// - mfr must be page-aligned.
func (apfs *AsyncPagesFileSave) combine(mfr apsRange) uint64 {
	op := apfs.curOp
	if op.total != 0 {
		if op.amfs != mfr.amfs {
			// Differing MemoryFile.
			return 0
		}
		if len(op.frs) == cap(op.frs) && op.frs[len(op.frs)-1].End != mfr.Start {
			// Non-contiguous in the MemoryFile, and we're out of space for
			// FileRanges.
			return 0
		}
	}

	// Apply direct length limits.
	n := mfr.Length()
	if op.total+n >= apfs.maxWriteBytes {
		n = apfs.maxWriteBytes - op.total
	}
	if n == 0 {
		return 0
	}
	mfr.End = mfr.Start + n

	// Collect iovecs, which may further limit length.
	n = 0
	mfr.amfs.f.forEachMappingSlice(mfr.FileRange, func(bs []byte) {
		if len(op.iovecs) > 0 {
			if canMergeIovecAndSlice(op.iovecs[len(op.iovecs)-1], bs) {
				op.iovecs[len(op.iovecs)-1].Len += uint64(len(bs))
				n += uint64(len(bs))
				return
			}
			if len(op.iovecs) == cap(op.iovecs) {
				return
			}
		}
		op.iovecs = append(op.iovecs, unix.Iovec{
			Base: &bs[0],
			Len:  uint64(len(bs)),
		})
		n += uint64(len(bs))
	})
	if n == 0 {
		return 0
	}
	mfr.End = mfr.Start + n

	// With the length decided, finish updating op.
	if op.total == 0 {
		op.amfs = mfr.amfs
	}
	op.total += n
	if len(op.frs) > 0 && op.frs[len(op.frs)-1].End == mfr.Start {
		op.frs[len(op.frs)-1].End = mfr.End
	} else {
		op.frs = append(op.frs, mfr.FileRange)
	}
	return n
}

func (apfs *AsyncPagesFileSave) main() {
	defer func() {
		if apfs.err != nil {
			log.Warningf("Async page saving failed: %w", apfs.err)
		}
		if err := apfs.aw.Close(); err != nil {
			// Saving success is independent of err, so log it rather than
			// propagating it.
			log.Warningf("Async page saving: stateio.AsyncWriter.Close failed: %v", err)
		}
		if apfs.doneCallback != nil {
			apfs.doneCallback(apfs.err)
		}
	}()

	maxParallel := apfs.aw.MaxParallel()
	// Storage reused between main loop iterations:
	var completions []stateio.Completion

	// Don't start timing until we have pages to save.
	apfs.stStatus.Wait()
	timeStart := gohacks.Nanotime()
	var bytesSaved atomicbitops.Uint64
	if log.IsLogging(log.Debug) {
		log.Debugf("Async page saving started")
		progressTicker := time.NewTicker(5 * time.Second)
		progressStopC := make(chan struct{})
		defer func() { close(progressStopC) }()
		go func() {
			timeLast := timeStart
			bytesSavedLast := uint64(0)
			for {
				select {
				case <-progressStopC:
					progressTicker.Stop()
					return
				case <-progressTicker.C:
					// Take a snapshot of our progress.
					bytesSavedNow := bytesSaved.Load()
					now := gohacks.Nanotime()
					durTotal := time.Duration(now - timeStart)
					durDelta := time.Duration(now - timeLast)
					bytesSavedDelta := bytesSavedNow - bytesSavedLast
					bandwidthTotal := float64(bytesSavedNow) * 1e-6 / durTotal.Seconds()
					bandwidthSinceLast := float64(bytesSavedDelta) * 1e-6 / durDelta.Seconds()
					log.Infof("Async page saving in progress for %s (%d bytes, %.3f MB/s); since last update %s ago: %d bytes, %.3f MB/s", durTotal.Round(time.Millisecond), bytesSavedNow, bandwidthTotal, durDelta.Round(time.Millisecond), bytesSavedDelta, bandwidthSinceLast)
					timeLast = now
					bytesSavedLast = bytesSavedNow
				}
			}
		}()
	}

	for {
		// Enqueue as many writes as possible.
		if !apfs.canEnqueue() {
			panic("main loop invariant failed")
		}
		apfs.mu.Lock()
		apfs.aw.Reserve(apfs.saveOff)
		for !apfs.unsaved.Empty() {
			mfr := apfs.unsaved.PeekFrontPtr()
			n := apfs.enqueueRange(*mfr)
			if n == mfr.Length() {
				apfs.unsaved.RemoveFront()
			} else if n != 0 {
				mfr.Start += n
			} else {
				break
			}
			if !apfs.canEnqueue() {
				break
			}
		}
		apfs.mu.Unlock()
		// Don't flush pending op unless it's the last one; this differs from
		// async page loading since writers are likely to be more sensitive to
		// write size than readers are to read size, and saving is less
		// latency-sensitive that loading.
		if apfs.curOp != nil && apfs.stStatus.Pending()&apsSTDone != 0 {
			apfs.enqueueCurOp()
		}

		if apfs.qavail == maxParallel {
			// We are out of work to do.
			ev := apfs.stStatus.Wait()
			if ev&apsSTPending != 0 {
				// We may have raced with MemoryFile.SaveTo() inserting into
				// apfs.unsaved.
				apfs.stStatus.Ack(apsSTPending)
				continue
			}
			if ev&apsSTDone != 0 {
				if apfs.curOp != nil {
					// Enqueue and complete the final write before finalizing.
					continue
				}
				if err := apfs.aw.Finalize(); err != nil {
					apfs.err = fmt.Errorf("stateio.AsyncWriter.Finalize failed: %w", err)
					return
				}
				// Successfully completed all saving for all MemoryFiles.
				durTotal := time.Duration(gohacks.Nanotime() - timeStart)
				bytesTotal := bytesSaved.RacyLoad()
				bandwidthTotal := float64(bytesTotal) * 1e-6 / durTotal.Seconds()
				log.Infof("Async page saving completed in %s (%d bytes, %.3f MB/s)", durTotal.Round(time.Millisecond), bytesTotal, bandwidthTotal)
				return
			}
			panic(fmt.Sprintf("unknown events in stStatus: %#x", ev))
		}

		// Wait for any number of writes to complete.
		var err error
		completions, err = apfs.aw.Wait(completions[:0], 1 /* minCompletions */)
		if err != nil {
			apfs.err = fmt.Errorf("stateio.AsyncWriter.Wait failed: %w", err)
			return
		}

		// Process completions.
		for _, c := range completions {
			op := &apfs.ops[c.ID]
			apfs.opsBusy.Remove(uint32(c.ID))
			apfs.qavail++
			if c.Err != nil {
				apfs.err = fmt.Errorf("write for MemoryFile(%p) pages %v failed: %w", op.amfs.f, op.frs, err)
				return
			}
			if c.N != op.total {
				apfs.err = fmt.Errorf("write for MemoryFile(%p) pages %v (total %d bytes) returned %d bytes", op.amfs.f, op.frs, op.total, c.N)
				return
			}
			bytesSaved.Add(op.total)
		}
	}
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
	fileSize := uint64(len(chunks)) * chunkSize
	if err := f.file.Truncate(int64(fileSize)); err != nil {
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
			uintptr(fileSize),
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
		var df stateio.DestinationFile
		if opts.PagesFile.ar.NeedRegisterDestinationFD() {
			var err error
			df, err = opts.PagesFile.ar.RegisterDestinationFD(int32(f.file.Fd()), fileSize, f.getClientFileRangeSettings(fileSize))
			if err != nil {
				return fmt.Errorf("failed to register MemoryFile with pages file: %w", err)
			}
		}
		amfl = &asyncMemoryFileLoad{
			f:        f,
			pf:       opts.PagesFile,
			df:       df,
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
		maFR := maseg.Range()
		amount := maFR.Length()
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
			// Verify header.
			length, object, err := state.ReadHeader(&wr)
			if err != nil {
				return fmt.Errorf("failed to read header: %w", err)
			}
			if object {
				// Not expected.
				return fmt.Errorf("unexpected object")
			}
			if length != amount {
				// Size mismatch.
				return fmt.Errorf("mismatched segment: expected %d, got %d", amount, length)
			}
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

	// lfStatus communicates MemoryFile.LoadFrom() state to the async page
	// loader goroutine.
	lfStatus syncevent.Waiter

	// Padding before state used mostly by the async page loader goroutine:
	_ [hostarch.CacheLineSize]byte

	// amfls tracks MemoryFiles that are currently loading from the pages file.
	// amfls is protected by amflsMu.
	amflsMu amflsMutex
	amfls   asyncMemoryFileLoadList

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

	// ar is the pages file. ar is immutable.
	ar stateio.AsyncReader

	// maxReadBytes is hostarch.PageRoundDown(ar.MaxReadBytes()), cached to
	// avoid interface method calls and recomputation. maxReadBytes is
	// immutable.
	maxReadBytes uint64

	// qavail is unused capacity in ar.
	qavail int

	// The async page loader combines multiple loads with contiguous pages file
	// offsets (the common case) into a single read, even if their
	// corresponding memmap.FileRanges and mappings are discontiguous. If curOp
	// is not nil, it is the current aplOp under construction, and curOpID is
	// its index into ops.
	curOp   *aplOp
	curOpID uint32

	// opsBusy tracks which aplOps in ops are in use (correspond to
	// inflight operations or curOp).
	opsBusy bitmap.Bitmap

	// ops stores all aplOps.
	ops []aplOp
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
	// Immutable fields:
	f        *MemoryFile
	pf       *AsyncPagesFileLoad
	df       stateio.DestinationFile
	timeline *timing.Timeline

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

	// frs are the MemoryFile ranges being loaded.
	frs []memmap.FileRange

	// iovecs contains mappings of frs.
	iovecs []unix.Iovec

	// If tempRef is true, a temporary reference is held on pages in frs that
	// should be dropped after completion.
	tempRef bool
}

func (op *aplOp) off() int64 {
	return int64(op.end - op.total)
}

// StartAsyncPagesFileLoad constructs asynchronous loading state for the pages
// file ar. It takes ownership of ar, even if it returns a non-nil error.
func StartAsyncPagesFileLoad(ar stateio.AsyncReader, doneCallback func(error), timeline *timing.Timeline) (*AsyncPagesFileLoad, error) {
	maxReadBytes := hostarch.PageRoundDown(ar.MaxReadBytes())
	if maxReadBytes <= 0 {
		ar.Close()
		return nil, fmt.Errorf("stateio.AsyncReader.MaxReadBytes() (%d) must be at least one page)", ar.MaxReadBytes())
	}
	// Cap maxParallel due to the uint32 range of bitmap.Bitmap.
	maxParallel := min(ar.MaxParallel(), 1<<30)
	apfl := &AsyncPagesFileLoad{
		timeline:     timeline.Fork("async page loading"),
		doneCallback: doneCallback,
		ar:           ar,
		maxReadBytes: maxReadBytes,
		qavail:       maxParallel,
		opsBusy:      bitmap.New(uint32(maxParallel)),
		ops:          make([]aplOp, maxParallel),
	}
	// Mark ops in opsBusy that don't actually exist as permanently busy.
	for i, n := maxParallel, apfl.opsBusy.Size(); i < n; i++ {
		apfl.opsBusy.Add(uint32(i))
	}
	// Pre-allocate slices in ops.
	maxRanges := ar.MaxRanges()
	for i := range apfl.ops {
		op := &apfl.ops[i]
		op.frs = make([]memmap.FileRange, 0, maxRanges)
		op.iovecs = make([]unix.Iovec, 0, maxRanges)
	}
	apfl.lfStatus.Init()
	go apfl.main()
	return apfl, nil
}

// MemoryFilesDone must be called after calling LoadFrom() for all MemoryFiles
// loading from apfl. MemoryFilesDone may be called multiple times; subsequent
// calls have no effect.
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
	if op.total > apfl.maxReadBytes {
		panic(fmt.Sprintf("read of %d bytes exceeds per-read limit of %d bytes", op.total, apfl.maxReadBytes))
	}

	apfl.qavail--
	apfl.curOp = nil
	if len(op.frs) == 1 && len(op.iovecs) == 1 {
		// Perform a non-vectorized read to save an indirection (and possible
		// userspace-to-kernelspace copy) in the AsyncReader implementation.
		apfl.ar.AddRead(int(apfl.curOpID), op.off(), op.amfl.df, op.frs[0], stateio.SliceFromIovec(op.iovecs[0]))
	} else {
		apfl.ar.AddReadv(int(apfl.curOpID), op.off(), op.total, op.amfl.df, op.frs, op.iovecs)
	}
	if logAwaitedLoads && !op.tempRef {
		log.Infof("MemoryFile(%p): awaited opid %d start, read %d bytes: %v", op.amfl.f, apfl.curOpID, op.total, op.frs)
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
			op.frs = op.frs[:0]
			op.iovecs = op.iovecs[:0]
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
			// Differing MemoryFile.
			return 0
		}
		if len(op.frs) == cap(op.frs) && op.frs[len(op.frs)-1].End != fr.Start {
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
	if op.total+n >= apfl.maxReadBytes {
		n = apfl.maxReadBytes - op.total
	}
	if n == 0 {
		return 0
	}
	fr.End = fr.Start + n

	// Collect iovecs, which may further limit length.
	n = 0
	amfl.f.forEachMappingSlice(fr, func(bs []byte) {
		if len(op.iovecs) > 0 {
			if canMergeIovecAndSlice(op.iovecs[len(op.iovecs)-1], bs) {
				op.iovecs[len(op.iovecs)-1].Len += uint64(len(bs))
				n += uint64(len(bs))
				return
			}
			if len(op.iovecs) == cap(op.iovecs) {
				return
			}
		}
		op.iovecs = append(op.iovecs, unix.Iovec{
			Base: &bs[0],
			Len:  uint64(len(bs)),
		})
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
	if len(op.frs) > 0 && op.frs[len(op.frs)-1].End == fr.Start {
		op.frs[len(op.frs)-1].End = fr.End
	} else {
		op.frs = append(op.frs, fr)
	}
	return n
}

func (apfl *AsyncPagesFileLoad) main() {
	defer func() {
		// Close ar first since this synchronously stops inflight I/O.
		if err := apfl.ar.Close(); err != nil {
			// Completed reads are complete irrespective of err, so log err
			// rather than propagating it.
			log.Warningf("Async page loading: stateio.AsyncReader.Close failed: %v", err)
		}
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

	maxParallel := apfl.ar.MaxParallel()
	// Storage reused between main loop iterations:
	var completions []stateio.Completion
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

		if apfl.qavail == maxParallel {
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
		completions, err = apfl.ar.Wait(completions[:0], 1 /* minCompletions */)
		if err != nil {
			log.Warningf("Async page loading failed: stateio.AsyncReader.Wait failed: %v", err)
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
				for _, fr := range op.frs {
					decRefs = append(decRefs, aplFileRange{op.amfl, fr})
				}
			}
			if c.N != op.total {
				log.Warningf("Async page loading failed: read for MemoryFile(%p) pages %v (total %d bytes) returned %d bytes, error: %v", op.amfl.f, op.frs, op.total, c.N, c.Err)
				apfl.errVal.Store(linuxerr.EIO)
				apfl.mu.Unlock()
				apfl.amflsMu.Unlock()
				return
			}
			apfl.bytesLoaded += op.total
			amfl := op.amfl
			haveWaiters := false
			now := int64(0)
			for _, fr := range op.frs {
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
				log.Infof("MemoryFile(%p): awaited opid %d complete, read %d bytes: %v", op.amfl.f, c.ID, op.total, op.frs)
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

func (f *MemoryFile) getClientFileRangeSettings(fileSize uint64) []stateio.ClientFileRangeSetting {
	if !f.opts.AdviseHugepage && !f.opts.AdviseNoHugepage {
		return nil
	}
	var cfrs []stateio.ClientFileRangeSetting
	f.forEachChunk(memmap.FileRange{0, fileSize}, func(chunk *chunkInfo, chunkFR memmap.FileRange) bool {
		if chunk.huge {
			if f.opts.AdviseHugepage {
				cfrs = append(cfrs, stateio.ClientFileRangeSetting{
					FileRange: chunkFR,
					Property:  stateio.PropertyHugepage,
				})
			}
		} else {
			if f.opts.AdviseNoHugepage {
				cfrs = append(cfrs, stateio.ClientFileRangeSetting{
					FileRange: chunkFR,
					Property:  stateio.PropertyNoHugepage,
				})
			}
		}
		return true
	})
	return cfrs
}
