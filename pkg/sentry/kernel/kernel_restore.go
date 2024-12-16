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
	k.CheckpointWait.signal(k.checkpointGen.Count, nil)
}

// OnCheckpointAttempt is called when a checkpoint attempt is completed. err is
// any checkpoint errors that may have occurred.
func (k *Kernel) OnCheckpointAttempt(err error) {
	k.checkpointMu.Lock()
	defer k.checkpointMu.Unlock()

	k.checkpointGen.Count++
	k.checkpointGen.Restore = false
	k.CheckpointWait.signal(k.checkpointGen.Count, err)
}

// WaitForCheckpoint waits for the Kernel to have been successfully checkpointed.
func (k *Kernel) WaitForCheckpoint() error {
	// Wait for the next checkpoint to complete.
	ch := k.CheckpointWait.Register(k.CheckpointGen().Count + 1)
	defer k.CheckpointWait.Unregister(ch)

	<-ch
	return k.CheckpointWait.result(ch)
}

type checkpointWaiter struct {
	// count indicates the checkpoint generation that this waiter is interested in.
	count uint32
	// ch is the channel that will be signalled when the checkpoint generation
	// reaches count.
	ch chan struct{}
	// err is the error (if any) that occurred during the checkpoint operation.
	err error
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
	waiters []checkpointWaiter `state:"nosave"`
}

// Register registers a waiter for the next checkpoint generation.
//
// Returns a channel that will be signalled when the checkpoint generation
// reaches count.
func (w *CheckpointWaitable) Register(count uint32) chan struct{} {
	w.mu.Lock()
	defer w.mu.Unlock()

	waiter := checkpointWaiter{
		count: count,
		ch:    make(chan struct{}, 1),
	}
	if count <= w.k.CheckpointGen().Count {
		// The checkpoint has already occurred. Signal immediately.
		waiter.ch <- struct{}{}
	}
	w.waiters = append(w.waiters, waiter)
	return waiter.ch
}

// Unregister unregisters a waiter. It must be called even if the channel
// was signalled.
func (w *CheckpointWaitable) Unregister(ch chan struct{}) {
	w.mu.Lock()
	defer w.mu.Unlock()

	for i, waiter := range w.waiters {
		if waiter.ch == ch {
			w.waiters = append(w.waiters[:i], w.waiters[i+1:]...)
			return
		}
	}
	panic("Unregistering a waiter that was not registered")
}

func (w *CheckpointWaitable) signal(count uint32, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	for _, c := range w.waiters {
		if c.count <= count {
			c.err = err
			c.ch <- struct{}{}
		}
	}
}

// result returns the error (or nil) of the checkpoint that signalled `ch`.
// Note: it will return nil if `ch` was never signalled.
func (w *CheckpointWaitable) result(ch chan struct{}) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	for _, waiter := range w.waiters {
		if waiter.ch == ch {
			return waiter.err
		}
	}
	panic("Unregistering a waiter that was never registered")
}
