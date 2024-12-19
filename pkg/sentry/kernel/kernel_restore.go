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
	"gvisor.dev/gvisor/pkg/log"
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
	// chekpoint failed.
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
