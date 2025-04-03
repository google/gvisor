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
	"errors"
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
	// KickoffPrivate attempts to kick off loading of private MemoryFiles
	// asynchronously, if possible. If not, this function is a no-op.
	// The private MemoryFile data must be known and within `ctx` by the point
	// this function is called.
	// This function does not need to be called within the lifecycle of
	// PagesFileLoader, but if it is, it must be called before Load.
	KickoffPrivate(ctx context.Context) error

	// Load loads the main MemoryFile and all private MemoryFiles.
	//
	// If loading operations were not kicked off asynchronously, this function
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
	//
	// Load must be called exactly once, and no further functions may be called
	// on PagesFileLoader after Load is called.
	Load(ctx context.Context, mainMf *pgalloc.MemoryFile, background bool) error
}

// singleStateFilePFL implements PagesFileLoader by loading MemoryFiles from a
// single state file.
type singleStateFilePFL struct {
	// source is the checkpoint source.
	source io.Reader
}

// KickoffPrivate is a no-op for this implementation.
func (*singleStateFilePFL) KickoffPrivate(ctx context.Context) error {
	return nil
}

// loadPrivateMemoryFiles loads the private MemoryFiles from ctx, which must
// contain MemoryFileMap metadata, and it reads private MemoryFile metadata
// from `r`. This consumes bytes from `r`, so this must be called only once.
func loadPrivateMemoryFiles(ctx context.Context, r io.Reader, mfmap map[string]*pgalloc.MemoryFile, opts *pgalloc.LoadOpts) error {
	// Load the metadata.
	var meta privateMemoryFileMetadata
	if _, err := state.Load(ctx, r, &meta); err != nil {
		return err
	}
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
func (pfl *singleStateFilePFL) Load(ctx context.Context, mainMf *pgalloc.MemoryFile, background bool) error {
	var opts pgalloc.LoadOpts
	if err := mainMf.LoadFrom(ctx, pfl.source, &opts); err != nil {
		return fmt.Errorf("failed to load main MemoryFile %p: %w", mainMf, err)
	}
	if err := loadPrivateMemoryFiles(ctx, pfl.source, pgalloc.MemoryFileMapFromContext(ctx), &opts); err != nil {
		return fmt.Errorf("failed to load private MemoryFiles: %w", err)
	}
	return nil
}

// NewSingleStateFilePagesFileLoader creates a new PagesFileLoader that loads
// MemoryFiles from a single state file synchronously.
// It does not take ownership of `source`, so the caller is responsible for
// closing it.
func NewSingleStateFilePagesFileLoader(source io.Reader) PagesFileLoader {
	return &singleStateFilePFL{
		source: source,
	}
}

// separatePagesFileLoader implements PagesFileLoader by loading MemoryFiles
// asynchronously thanks to having separate pages and page metadata files,
// as opposed to a single state file containing everything.
type separatePagesFileLoader struct {
	// loadPrivateMFs is used to communicate with the background goroutine
	// once private MemoryFiles are known.
	loadPrivateMFs sync.Once

	// privateMFsChan is used to tell the background goroutine about
	// private MemoryFiles, once they are known.
	// This channel is written to exactly once as part of `loadPrivateMFs`.
	privateMFsChan chan map[string]*pgalloc.MemoryFile

	// loadResultCh is the channel used by the background goroutine to report
	// load errors. In normal successful operation, this channel will be written
	// exactly two `nil` values: one once all MemoryFile *metadata* has been
	// loaded, and one when all MemoryFile pages have been loaded.
	// Then the channel will be closed.
	// If any actual error occurs, this channel will have this error written to
	// it, and then closed.
	loadResultCh chan error
}

// NewSeparatePagesFileLoader creates a new PageFileLoader that loads
// MemoryFiles asynchronously from separate pages and page metadata files.
// It takes ownership of pagesMetadata and pagesFile.
func NewSeparatePagesFileLoader(pagesMetadata, pagesFile *fd.FD, mainMF *pgalloc.MemoryFile) PagesFileLoader {
	pfl := &separatePagesFileLoader{
		privateMFsChan: make(chan map[string]*pgalloc.MemoryFile, 1),
		loadResultCh:   make(chan error, 2),
	}
	go func() {
		defer close(pfl.loadResultCh)
		defer pagesMetadata.Close()
		defer pagesFile.Close()
		pfl.loadResultCh <- pfl.backgroundGoroutine(pagesMetadata, pagesFile, mainMF)
	}()
	return pfl
}

func (pfl *separatePagesFileLoader) backgroundGoroutine(pagesMetadataFD, pagesFileFD *fd.FD, mainMF *pgalloc.MemoryFile) error {
	ctx := context.Background()
	var wg sync.WaitGroup
	var loadErrsMu sync.Mutex
	var loadErrs []error

	// //pkg/state/wire reads one byte at a time; buffer these reads to
	// avoid making one syscall per read. For the "main" state file, this
	// buffering is handled by statefile.NewReader() => compressio.Reader
	// or compressio.NewSimpleReader().
	pagesMetadata := bufio.NewReader(pagesMetadataFD)

	opts := pgalloc.LoadOpts{
		PagesFile: pagesFileFD,
		OnAsyncPageLoadStart: func(mf *pgalloc.MemoryFile) {
			wg.Add(1)
			log.Infof("Starting async page load for %p", mf)
		},
		OnAsyncPageLoadDone: func(mf *pgalloc.MemoryFile, err error) {
			defer wg.Done()
			if err != nil {
				log.Warningf("Async page load error for %p: %v", mf, err)
				loadErrsMu.Lock()
				loadErrs = append(loadErrs, fmt.Errorf("%p: async page load: %w", mf, err))
				loadErrsMu.Unlock()
			}
		},
	}

	log.Infof("Loading metadata for main MemoryFile: %p", mainMF)
	if err := mainMF.LoadFrom(ctx, pagesMetadata, &opts); err != nil {
		log.Warningf("Failed to load main MemoryFile %p: %v", mainMF, err)
		return err
	}

	privateMFs := <-pfl.privateMFsChan
	log.Infof("Loading metadata for %d private MemoryFiles", len(privateMFs))
	if err := loadPrivateMemoryFiles(ctx, pagesMetadata, privateMFs, &opts); err != nil {
		log.Warningf("Failed to load private MemoryFiles: %v", err)
		return err
	}

	// Report metadata load completion.
	log.Infof("All MemoryFile metadata has been loaded")
	pfl.loadResultCh <- nil

	// Wait for page loads to complete and report errors.
	wg.Wait()
	loadErrsMu.Lock()
	defer loadErrsMu.Unlock()
	if loadErr := errors.Join(loadErrs...); loadErr != nil {
		return loadErr
	}
	log.Infof("All MemoryFile pages have been loaded.")
	return nil
}

// KickoffPrivate implements PagesFileLoader.KickoffPrivate.
func (pfl *separatePagesFileLoader) KickoffPrivate(ctx context.Context) error {
	pfl.loadPrivateMFs.Do(func() {
		pfl.privateMFsChan <- pgalloc.MemoryFileMapFromContext(ctx)
	})
	return nil
}

// Load implements PagesFileLoader.Load.
func (pfl *separatePagesFileLoader) Load(ctx context.Context, mainMf *pgalloc.MemoryFile, background bool) error {
	if err := pfl.KickoffPrivate(ctx); err != nil {
		return err
	}

	// First error from loadResultCh is about MemoryFile metadata.
	if err := <-pfl.loadResultCh; err != nil {
		return fmt.Errorf("failed to load MemoryFile metadata: %w", err)
	}

	// Second error from loadResultCh is about MemoryFile pages.
	// We only wait for it if `background=false`.
	if !background {
		if err := <-pfl.loadResultCh; err != nil {
			return fmt.Errorf("failed to load MemoryFile pages: %w", err)
		}
		return nil
	}
	log.Infof("All page load work has been kicked off successfully in the background.")
	return nil
}
