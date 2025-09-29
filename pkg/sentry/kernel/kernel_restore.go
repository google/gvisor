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
	"fmt"
	"io"

	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/state/stateio"
	"gvisor.dev/gvisor/pkg/state"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/timing"
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

// IncCheckpointGenOnRestore increments the checkpoint generation upon restore.
func (k *Kernel) IncCheckpointGenOnRestore() {
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

// loadPrivateMemoryFiles loads the private MemoryFiles from mfmap and it reads
// private MemoryFile metadata from `r`. This consumes bytes from `r`, so this
// must be called only once.
func loadPrivateMemoryFiles(ctx context.Context, r io.Reader, mfmap map[string]*pgalloc.MemoryFile, opts *pgalloc.LoadOpts) error {
	// Load the metadata.
	var meta privateMemoryFileMetadata
	if _, err := state.Load(ctx, r, &meta); err != nil {
		return err
	}
	// Ensure that it is consistent with mfmap.
	if len(mfmap) != len(meta.owners) {
		return fmt.Errorf("inconsistent private memory files on restore: savedMFOwners = %v, mfmap = %v", meta.owners, mfmap)
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

func (k *Kernel) loadMemoryFiles(ctx context.Context, r io.Reader) error {
	var opts pgalloc.LoadOpts
	if err := k.mf.LoadFrom(ctx, r, &opts); err != nil {
		return fmt.Errorf("failed to load main MemoryFile %p: %w", k.mf, err)
	}
	if err := loadPrivateMemoryFiles(ctx, r, pgalloc.MemoryFileMapFromContext(ctx), &opts); err != nil {
		return fmt.Errorf("failed to load private MemoryFiles: %w", err)
	}
	return nil
}

// AsyncMFLoader loads all MemoryFiles asynchronously; thanks to having
// separate pages and page metadata files, as opposed to a single state file
// containing everything.
//
// The AsyncMFLoader helps achieve the following goals:
//   - Loading the main MemoryFile as early as possible.
//   - Loading the private MemoryFiles, also as early as possible but after
//     the main MemoryFile.
//   - Wait for various events to occur before proceeding.
//   - Report errors as they occur.
type AsyncMFLoader struct {
	// privateMFsChan is used to tell the background goroutine about private
	// MemoryFiles, once they are known. This channel is written to exactly once.
	privateMFsChan chan map[string]*pgalloc.MemoryFile

	mainMFStartWg   sync.WaitGroup
	mainMetadataErr error

	metadataWg  sync.WaitGroup
	metadataErr error

	loadWg  sync.WaitGroup
	loadErr error
}

// NewAsyncMFLoader creates a new AsyncMFLoader. It takes ownership of
// pagesMetadata and pagesFile. It creates a background goroutine that will
// load all the MemoryFiles. The background goroutine immediately starts
// loading the main MemoryFile.
// If timeline is provided, it will be used to track async page loading.
// It takes ownership of the timeline, and will end it when done loading all
// pages.
func NewAsyncMFLoader(pagesMetadata io.ReadCloser, pagesFile stateio.AsyncReader, mainMF *pgalloc.MemoryFile, timeline *timing.Timeline) *AsyncMFLoader {
	mfl := &AsyncMFLoader{
		privateMFsChan: make(chan map[string]*pgalloc.MemoryFile, 1),
	}
	mfl.mainMFStartWg.Add(1)
	mfl.metadataWg.Add(1)
	mfl.loadWg.Add(1)
	go mfl.backgroundGoroutine(pagesMetadata, pagesFile, mainMF, timeline)
	return mfl
}

func (mfl *AsyncMFLoader) backgroundGoroutine(pagesMetadata io.ReadCloser, pagesFile stateio.AsyncReader, mainMF *pgalloc.MemoryFile, timeline *timing.Timeline) {
	defer timeline.End()
	defer pagesMetadata.Close()
	cu := cleanup.Make(func() {
		mfl.metadataWg.Done()
		mfl.loadWg.Done()
	})
	defer cu.Clean()

	mfl.loadWg.Add(1)
	apfl, err := pgalloc.StartAsyncPagesFileLoad(pagesFile, func(err error) {
		defer mfl.loadWg.Done()
		mfl.loadErr = err
	}, timeline) // transfers ownership of pagesFile
	if err != nil {
		mfl.loadWg.Done()
		log.Warningf("Failed to start async page loading: %v", err)
		return
	}
	cu.Add(apfl.MemoryFilesDone)

	opts := pgalloc.LoadOpts{
		PagesFile: apfl,
		Timeline:  timeline,
	}

	timeline.Reached("loading mainMF")
	log.Infof("Loading metadata for main MemoryFile: %p", mainMF)
	ctx := context.Background()
	err = mainMF.LoadFrom(ctx, pagesMetadata, &opts)
	mfl.metadataErr = err
	mfl.mainMetadataErr = err
	mfl.mainMFStartWg.Done()
	if err != nil {
		log.Warningf("Failed to load main MemoryFile %p: %v", mainMF, err)
		return
	}
	timeline.Reached("waiting for privateMF info")
	privateMFs := <-mfl.privateMFsChan
	timeline.Reached("received privateMFs info")
	log.Infof("Loading metadata for %d private MemoryFiles", len(privateMFs))
	if err := loadPrivateMemoryFiles(ctx, pagesMetadata, privateMFs, &opts); err != nil {
		log.Warningf("Failed to load private MemoryFiles: %v", err)
		mfl.metadataErr = err
		return
	}

	// Report metadata load completion.
	timeline.Reached("metadata load done")
	log.Infof("All MemoryFile metadata has been loaded")
	cu.Release()()

	// Wait for page loads to complete and report errors.
	mfl.loadWg.Wait()
	if mfl.loadErr != nil {
		timeline.Invalidate("page load failed")
		log.Warningf("Failed to load MemoryFile pages: %v", mfl.loadErr)
		return
	}
	log.Infof("All MemoryFile pages have been loaded.")
}

// KickoffPrivate notifies the background goroutine of the private MemoryFiles.
func (mfl *AsyncMFLoader) KickoffPrivate(mfmap map[string]*pgalloc.MemoryFile) {
	mfl.privateMFsChan <- mfmap
}

// WaitMainMFStart waits for the background goroutine to successfully start
// asynchronously loading the main MemoryFile.
func (mfl *AsyncMFLoader) WaitMainMFStart() error {
	mfl.mainMFStartWg.Wait()
	return mfl.mainMetadataErr
}

// WaitMetadata waits for the background goroutine to successfully complete
// reading all MemoryFile metadata and report any errors.
func (mfl *AsyncMFLoader) WaitMetadata() error {
	mfl.metadataWg.Wait()
	return mfl.metadataErr
}

// Wait waits for the background goroutine to successfully complete fully
// loading all the MemoryFiles and report any errors.
func (mfl *AsyncMFLoader) Wait() error {
	if err := mfl.WaitMetadata(); err != nil {
		return err
	}
	mfl.loadWg.Wait()
	return mfl.loadErr
}
