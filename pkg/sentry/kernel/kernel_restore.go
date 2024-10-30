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

// Saver is an interface for saving the kernel.
type Saver interface {
	SaveAsync() error
	SpecEnviron(containerName string) []string
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

// IncCheckpointCount increments the checkpoint counter.
func (k *Kernel) IncCheckpointCount() {
	k.checkpointMu.Lock()
	defer k.checkpointMu.Unlock()
	k.checkpointCounter++
}

// CheckpointCount returns the current checkpoint count. Note that the result
// may be stale by the time the caller uses it.
func (k *Kernel) CheckpointCount() uint32 {
	k.checkpointMu.Lock()
	defer k.checkpointMu.Unlock()
	return k.checkpointCounter
}

// OnCheckpointAttempt is called when a checkpoint attempt is completed. err is
// any checkpoint errors that may have occurred.
func (k *Kernel) OnCheckpointAttempt(err error) {
	k.checkpointMu.Lock()
	defer k.checkpointMu.Unlock()
	if err == nil {
		k.checkpointCounter++
	}
	k.lastCheckpointStatus = err
	k.checkpointCond.Broadcast()
}

// ResetCheckpointStatus resets the last checkpoint status, indicating a new
// checkpoint is in progress. Caller must call OnCheckpointAttempt when the
// checkpoint attempt is completed.
func (k *Kernel) ResetCheckpointStatus() {
	k.checkpointMu.Lock()
	defer k.checkpointMu.Unlock()
	k.lastCheckpointStatus = nil
}

// WaitCheckpoint waits for the Kernel to have been successfully checkpointed
// n-1 times, then waits for either the n-th successful checkpoint (in which
// case it returns nil) or any number of failed checkpoints (in which case it
// returns an error returned by any such failure).
func (k *Kernel) WaitCheckpoint(n uint32) error {
	if n == 0 {
		return nil
	}
	k.checkpointMu.Lock()
	defer k.checkpointMu.Unlock()
	if k.checkpointCounter >= n {
		// n-th checkpoint already completed successfully.
		return nil
	}
	for k.checkpointCounter < n {
		if k.checkpointCounter == n-1 && k.lastCheckpointStatus != nil {
			// n-th checkpoint was attempted but it had failed.
			return k.lastCheckpointStatus
		}
		k.checkpointCond.Wait()
	}
	return nil
}
