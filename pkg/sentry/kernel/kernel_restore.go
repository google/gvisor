// Copyright 2024 The gVisor Authors.
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
	"bufio"
	"fmt"
	"io"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/state"
	"gvisor.dev/gvisor/pkg/sync"
)

// Saver is an interface for saving the kernel.
type Saver interface {
	SaveAsync() error
	SpecEnviron(containerName string) []string
}

// CheckpointGeneration stores information about the last checkpoint taken.
//
// +stateify savable
type CheckpointGeneration struct {
	// Count is incremented every time a checkpoint is triggered, even if the
	// checkpoint failed.
	Count uint32
	// Restore indicates if the current instance resumed after the checkpoint or
	// it was restored from a checkpoint.
	Restore bool
}

// AddStateToCheckpoint adds a key-value pair to be additionally checkpointed.
func (k *Kernel) AddStateToCheckpoint(key, v any) {
	k.checkpointMu.Lock()
	defer k.checkpointMu.Unlock()
	if k.additionalCheckpointState == nil {
		k.additionalCheckpointState = make(map[any]any)
	}
	k.additionalCheckpointState[key] = v
}

// PopCheckpointState pops a key-value pair from the additional checkpoint
// state. If the key doesn't exist, nil is returned.
func (k *Kernel) PopCheckpointState(key any) any {
	k.checkpointMu.Lock()
	defer k.checkpointMu.Unlock()
	if v, ok := k.additionalCheckpointState[key]; ok {
		delete(k.additionalCheckpointState, key)
		return v
	}
	return nil
}

// SetSaver sets the kernel's Saver.
// Thread-compatible.
func (k *Kernel) SetSaver(s Saver) {
	k.checkpointMu.Lock()
	defer k.checkpointMu.Unlock()
	k.saver = s
}

// Saver returns the kernel's Saver.
// Thread-compatible.
func (k *Kernel) Saver() Saver {
	k.checkpointMu.Lock()
	defer k.checkpointMu.Unlock()
	return k.saver
}

// CheckpointGen returns the current checkpoint generation.
func (k *Kernel) CheckpointGen() CheckpointGeneration {
	k.checkpointMu.Lock()
	defer k.checkpointMu.Unlock()

	return k.checkpointGen
}

// OnRestoreDone is called to notify the kernel that a checkpoint restore has been
// completed successfully.
func (k *Kernel) OnRestoreDone() {
	k.checkpointMu.Lock()
	defer k.checkpointMu.Unlock()

	k.checkpointGen.Count++
	k.checkpointGen.Restore = true

	k.CheckpointWait.signal(k.checkpointGen, nil)
}

// OnCheckpointAttempt is called when a checkpoint attempt is completed. err is
// any checkpoint errors that may have occurred.
func (k *Kernel) OnCheckpointAttempt(err error) {
	if err == nil {
		log.Infof("Checkpoint completed successfully.")
	} else {
		log.Warningf("Checkpoint attempt failed with error: %v", err)
	}

	k.checkpointMu.Lock()
	defer k.checkpointMu.Unlock()

	k.checkpointGen.Count++
	k.checkpointGen.Restore = false

	k.CheckpointWait.signal(k.checkpointGen, err)
}

// WaitForCheckpoint waits for the Kernel to have been successfully checkpointed.
func (k *Kernel) WaitForCheckpoint() error {
	// Send checkpoint result to a channel and wait on it.
	ch := make(chan error, 1)
	callback := func(_ CheckpointGeneration, err error) { ch <- err }
	key := k.CheckpointWait.Register(callback, k.CheckpointGen().Count+1)
	defer k.CheckpointWait.Unregister(key)

	return <-ch
}

type checkpointWaiter struct {
	// count indicates the checkpoint generation that this waiter is interested in.
	count uint32
	// callback is the function that will be called when the checkpoint generation
	// reaches the desired count. It is set to nil after the callback is called.
	callback func(CheckpointGeneration, error)
}

// CheckpointWaitable is a waitable object that waits for a
// checkpoint to complete.
//
// +stateify savable
type CheckpointWaitable struct {
	k *Kernel

	mu sync.Mutex `state:"nosave"`

	// Don't save the waiters, because they are repopulated after restore. It also
	// allows for external entities to wait for the checkpoint.
	waiters map[*checkpointWaiter]struct{} `state:"nosave"`
}

// Register registers a callback that is notified when the checkpoint generation count is higher
// than the desired count.
func (w *CheckpointWaitable) Register(cb func(CheckpointGeneration, error), count uint32) any {
	w.mu.Lock()
	defer w.mu.Unlock()

	waiter := &checkpointWaiter{
		count:    count,
		callback: cb,
	}
	if w.waiters == nil {
		w.waiters = make(map[*checkpointWaiter]struct{})
	}
	w.waiters[waiter] = struct{}{}

	if gen := w.k.CheckpointGen(); count <= gen.Count {
		// The checkpoint has already occurred. Signal immediately.
		waiter.callback(gen, nil)
		waiter.callback = nil
	}
	return waiter
}

// Unregister unregisters a waiter. It must be called even if the channel
// was signalled.
func (w *CheckpointWaitable) Unregister(key any) {
	w.mu.Lock()
	defer w.mu.Unlock()

	delete(w.waiters, key.(*checkpointWaiter))
	if len(w.waiters) == 0 {
		w.waiters = nil
	}
}

func (w *CheckpointWaitable) signal(gen CheckpointGeneration, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	for waiter := range w.waiters {
		if waiter.callback != nil && waiter.count <= gen.Count {
			waiter.callback(gen, err)
			waiter.callback = nil
		}
	}
}

const (
	// maxMemoryFiles is the maximum number of MemoryFiles that can be loaded.
	maxMemoryFiles = 1024
)

// PagesFileLoader coordinates the process of loading pages into MemoryFiles,
// possibly asynchronously.
//
// It is used to load pages from checkpoint (whether through a separate file
// or the main state file) into one or more MemoryFiles.
//
// Lifecycle:
// PagesFileLoader may be created as soon as a primary MemoryFile is known
// and a state file is opened.
//
// The PagesFileLoader has three jobs:
//   - Loading the main MemoryFile as early as possible.
//   - Loading the private MemoryFiles, also as early as possible but after
//     the main MemoryFile.
//   - Ensuring that the above is done by a certain point of the restore
//     process.
type PagesFileLoader interface {
	// LoadMainAsync attempts to kick off loading of the main MemoryFile
	// asynchronously, if possible. If not, this function is a no-op.
	// This function does not need to be called, but if it is, it must be
	// called before Load.
	LoadMainAsync(ctx context.Context, mf *pgalloc.MemoryFile) error

	// LoadAllAsync attempts to kick off loading of the main MemoryFile and all
	// private MemoryFiles asynchronously, if possible. If not, this function is
	// a no-op.
	// This function does not need to be called, but if it is, it must be
	// called before Load.
	LoadAllAsync(ctx context.Context, mainMf *pgalloc.MemoryFile) error

	// Load loads the main MemoryFile and all private MemoryFiles.
	// If these operations were not kicked off asynchronously, this function
	// will perform them synchronously. `background` is ignored in this case.
	//
	// If they were kicked off asynchronously, this function will wait for them
	// instead, with `background` controlling how early this function returns:
	//
	//   - If `background` is false, this function will return after both pages
	//     metadata and pages themselves have been loaded.
	//   - If `background` is true, this function will return after the main
	//     MemoryFile and all private MemoryFiles have had their metadata
	//     loaded, but will not wait for their pages to be loaded.
	Load(ctx context.Context, mainMf *pgalloc.MemoryFile, background bool) error
}

// pagesFileLoader implements PagesFileLoader by loading MemoryFiles from a
// single state file.
type pagesFileLoader struct {
	// source is the checkpoint source.
	source io.Reader
}

// LoadMainAsync is a no-op for this implementation.
func (*pagesFileLoader) LoadMainAsync(ctx context.Context, mf *pgalloc.MemoryFile) error {
	return nil
}

// LoadAllAsync is a no-op for this implementation.
func (*pagesFileLoader) LoadAllAsync(ctx context.Context, mainMf *pgalloc.MemoryFile) error {
	return nil
}

// loadPrivateMemoryFiles loads the private MemoryFiles from ctx, which must
// contain MemoryFileMap metadata, and it reads private MemoryFile metadata
// from `r`. This consumes bytes from `r`, so this must be called only once.
func loadPrivateMemoryFiles(ctx context.Context, r io.Reader, opts *pgalloc.LoadOpts) error {
	// Load the metadata.
	var meta privateMemoryFileMetadata
	if _, err := state.Load(ctx, r, &meta); err != nil {
		return err
	}
	mfmap := pgalloc.MemoryFileMapFromContext(ctx)
	// Ensure that it is consistent with CtxFilesystemMemoryFileMap.
	if len(mfmap) != len(meta.owners) {
		return fmt.Errorf("inconsistent private memory files on restore: savedMFOwners = %v, CtxFilesystemMemoryFileMap = %v", meta.owners, mfmap)
	}
	// Load all private memory files.
	for _, fsID := range meta.owners {
		mf, ok := mfmap[fsID]
		if !ok {
			return fmt.Errorf("saved private memory file for %q was not configured on restore", fsID)
		}
		err := mf.LoadFrom(ctx, r, opts)
		if err != nil {
			return fmt.Errorf("failed to load MemoryFile %p fsID %q: %w", mf, fsID, err)
		}
	}
	return nil
}

// Load loads the main MemoryFile and all private MemoryFiles synchronously.
func (pfl *pagesFileLoader) Load(ctx context.Context, mainMf *pgalloc.MemoryFile, background bool) error {
	var opts pgalloc.LoadOpts
	if err := mainMf.LoadFrom(ctx, pfl.source, &opts); err != nil {
		return fmt.Errorf("failed to load main MemoryFile %p: %w", mainMf, err)
	}
	if err := loadPrivateMemoryFiles(ctx, pfl.source, &opts); err != nil {
		return fmt.Errorf("failed to load private MemoryFiles: %w", err)
	}
	return nil
}

// NewPagesFileLoader creates a new PagesFileLoader that loads MemoryFiles
// from a single state file synchronously.
// It does not take ownership of `source`, so the caller is responsible for
// closing it.
func NewPagesFileLoader(source io.Reader) PagesFileLoader {
	return &pagesFileLoader{
		source: source,
	}
}

// asyncPagesFileLoader implements PagesFileLoader by loading MemoryFiles
// asynchronously.
type asyncPagesFileLoader struct {
	// pagesMetadata points to a separate file that can contain page metadata.
	pagesMetadata *bufio.Reader

	// pagesMetadataClose is the function to close the pagesMetadata file.
	pagesMetadataClose func() error

	// pagesFile contains page data.
	pagesFile *fd.FD

	// mainMfMetadataWG is used to wait for the main MemoryFile to have its
	// metadata asynchronously loaded. This does *not* wait for the main
	// MemoryFile to have its pages loaded.
	mainMfMetadataWG sync.WaitGroup

	// privateMfMetadataWG is used to wait for the private MemoryFiles to have
	// their metadata asynchronously loaded. This does *not* wait for the private
	// MemoryFiles to have their pages loaded.
	privateMfMetadataWG sync.WaitGroup

	// asyncPageLoadWG is used to wait for all asynchronous page loads to
	// complete.
	asyncPageLoadWG sync.WaitGroup

	// mu protects the following fields.
	mu sync.Mutex

	// mainMf is the main MemoryFile to load.
	// Initially nil, set once the main MemoryFile has been enqueued for
	// asynchronous loading.
	mainMf *pgalloc.MemoryFile

	// mainMfMetadataError is the error that occurred during asynchronous
	// loading of the metadata of the main MemoryFile.
	// Valid under `mu` iff
	// (`mainMf` is set && (`mainMfMetadataWG` is done || `mainMfMetadataError` != nil).
	mainMfMetadataError error

	// mainMfLoadedBytes is the number of bytes loaded from the main MemoryFile.
	// Valid under `mu` iff (`mainMf` is set && `mainMfMetadataWG` is done &&
	// `mainMfMetadataError` is nil).
	mainMfLoadedBytes uint64

	// spawnedPrivateLoad indicates that the goroutine that will load the
	// private MemoryFiles has been spawned.
	spawnedPrivateLoad bool

	// privateMfMetadataError is the error that occurred during asynchronous
	// loading of the metadata of the private MemoryFiles.
	// Valid under `mu` iff
	// (`spawnedPrivateLoad` is true && (`privateMfMetadataWG` is done || `privateMfMetadataError` != nil).
	privateMfMetadataError error

	// asyncPageLoadErrors is the list of errors that occurred during
	// asynchronous page loading.
	// Valid under `mu` iff
	// `asyncPageLoadWG` is done && `mainMfMetadataError` is valid && `privateMfMetadataError` is valid.
	asyncPageLoadErrors []error
}

// NewAsyncPageFileLoader creates a new PageFileLoader that loads MemoryFiles
// asynchronously.
// It takes ownership of pagesMetadata and pagesFile.
func NewAsyncPageFileLoader(pagesMetadata, pagesFile *fd.FD) PagesFileLoader {
	return &asyncPagesFileLoader{
		// //pkg/state/wire reads one byte at a time; buffer these reads to
		// avoid making one syscall per read. For the "main" state file, this
		// buffering is handled by statefile.NewReader() => compressio.Reader
		// or compressio.NewSimpleReader().
		pagesMetadata:      bufio.NewReader(pagesMetadata),
		pagesMetadataClose: pagesMetadata.Close,
		pagesFile:          pagesFile,
	}
}

// asyncPageLoadStart returns a function to be called when an asynchronous
// page loading operation starts.
func (pfl *asyncPagesFileLoader) asyncPageLoadStart(name string) func() {
	return func() {
		log.Infof("Starting async page load for %s", name)
		pfl.asyncPageLoadWG.Add(1)
	}
}

// asyncPageLoadDone is called when one asynchronous page loading operation
// completes.
func (pfl *asyncPagesFileLoader) asyncPageLoadDone(err error) {
	if err != nil {
		log.Warningf("Async page load error: %v", err)
		pfl.mu.Lock()
		pfl.asyncPageLoadErrors = append(pfl.asyncPageLoadErrors, err)
		pfl.mu.Unlock()
	}
	pfl.asyncPageLoadWG.Done()
}

// LoadMainAsync kicks off loading of the main MemoryFile asynchronously.
func (pfl *asyncPagesFileLoader) LoadMainAsync(ctx context.Context, mf *pgalloc.MemoryFile) error {
	pfl.mu.Lock()
	defer pfl.mu.Unlock()
	if pfl.mainMf != nil {
		if pfl.mainMf != mf {
			return fmt.Errorf("main MemoryFile %p does not match previously set MemoryFile %p", mf, pfl.mainMf)
		}
		return pfl.mainMfMetadataError
	}
	log.Infof("Kicking off loading of main MemoryFile %p asynchronously.", mf)
	pfl.mainMf = mf
	pfl.mainMfMetadataWG.Add(1)
	go func() {
		defer pfl.mainMfMetadataWG.Done()
		opts := pgalloc.LoadOpts{
			PagesFile:            pfl.pagesFile,
			OnAsyncPageLoadStart: pfl.asyncPageLoadStart(fmt.Sprintf("main MemoryFile %p", mf)),
			OnAsyncPageLoadDone: func(err error) {
				if err != nil {
					pfl.asyncPageLoadDone(fmt.Errorf("failed to load main MemoryFile %p: %w", mf, err))
				} else {
					pfl.asyncPageLoadDone(nil)
				}
			},
		}
		err := mf.LoadFrom(ctx, pfl.pagesMetadata, &opts)
		if err != nil {
			log.Warningf("Failed to load main MemoryFile %p: %v", mf, err)
		}
		pfl.mu.Lock()
		defer pfl.mu.Unlock()
		pfl.mainMfMetadataError = err
		pfl.mainMfLoadedBytes = opts.PagesFileOffset
	}()
	return nil
}

// LoadAllAsync kicks off loading of the main MemoryFile and then all private
// MemoryFiles asynchronously.
func (pfl *asyncPagesFileLoader) LoadAllAsync(ctx context.Context, mainMf *pgalloc.MemoryFile) error {
	if err := pfl.LoadMainAsync(ctx, mainMf); err != nil {
		return err
	}
	pfl.mu.Lock()
	defer pfl.mu.Unlock()
	if pfl.mainMfMetadataError != nil {
		return pfl.mainMfMetadataError
	}
	if pfl.spawnedPrivateLoad {
		return pfl.privateMfMetadataError
	}
	log.Infof("Kicking off loading of private MemoryFiles asynchronously.")
	pfl.spawnedPrivateLoad = true
	pfl.privateMfMetadataWG.Add(1)
	go func() {
		defer pfl.privateMfMetadataWG.Done()
		pfl.mainMfMetadataWG.Wait()

		pfl.mu.Lock()
		mainMfMetadataError := pfl.mainMfMetadataError
		startingOffset := pfl.mainMfLoadedBytes
		pfl.mu.Unlock()

		if mainMfMetadataError != nil {
			log.Warningf("Failed to load main MemoryFile, so giving up on loading private MemoryFiles: %v", mainMfMetadataError)
			return
		}
		opts := pgalloc.LoadOpts{
			PagesFile:            pfl.pagesFile,
			PagesFileOffset:      startingOffset,
			OnAsyncPageLoadStart: pfl.asyncPageLoadStart("private MemoryFiles"),
			OnAsyncPageLoadDone: func(err error) {
				if err != nil {
					pfl.asyncPageLoadDone(fmt.Errorf("failed to load private MemoryFiles: %w", err))
				} else {
					pfl.asyncPageLoadDone(nil)
				}
			},
		}
		err := loadPrivateMemoryFiles(ctx, pfl.pagesMetadata, &opts)
		if err != nil {
			log.Warningf("Failed to load private MemoryFiles: %v", err)
		}
		pfl.mu.Lock()
		defer pfl.mu.Unlock()
		pfl.privateMfMetadataError = err
	}()
	return nil
}

// Load loads all MemoryFiles.
// If `background` is true, this function will return after the main
// MemoryFile and all private MemoryFiles have had their metadata loaded,
// but will not wait for their pages to be loaded.
// In this case, the pages metadata file will be closed after this function
// returns, but the pages file will remain open until page loading actually
// completes, at which point it will be closed.
// If `background` is false, this function will return after both pages
// metadata and pages themselves have been loaded.
// In this case, both the pages metadata and pages files will be closed after
// this function returns.
func (pfl *asyncPagesFileLoader) Load(ctx context.Context, mainMf *pgalloc.MemoryFile, background bool) error {
	defer pfl.pagesMetadataClose()
	if err := pfl.LoadAllAsync(ctx, mainMf); err != nil {
		return err
	}
	pfl.mainMfMetadataWG.Wait()
	pfl.privateMfMetadataWG.Wait()

	pfl.mu.Lock()
	mainMfMetadataError := pfl.mainMfMetadataError
	privateMfMetadataError := pfl.privateMfMetadataError
	pfl.mu.Unlock()

	if mainMfMetadataError != nil {
		return mainMfMetadataError
	}
	if privateMfMetadataError != nil {
		return privateMfMetadataError
	}

	waitFn := func() error {
		defer pfl.pagesFile.Close()
		pfl.asyncPageLoadWG.Wait()
		pfl.mu.Lock()
		defer pfl.mu.Unlock()
		if len(pfl.asyncPageLoadErrors) > 0 {
			if len(pfl.asyncPageLoadErrors) == 1 {
				return fmt.Errorf("failed to load MemoryFiles: %w", pfl.asyncPageLoadErrors[0])
			}
			return fmt.Errorf("failed to load MemoryFiles: %v", pfl.asyncPageLoadErrors)
		}
		return nil
	}
	if !background {
		log.Infof("All page load work has been kicked off successfully. Waiting for it to finish.")
		return waitFn()
	}
	log.Infof("All page load work has been kicked off successfully in the background.")
	go func() {
		if err := waitFn(); err != nil {
			log.Warningf("Failed to load MemoryFiles: %v", err)
		} else {
			log.Infof("All MemoryFiles have been loaded successfully.")
		}
	}()
	return nil
}
