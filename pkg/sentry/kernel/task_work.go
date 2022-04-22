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

// TaskWorker is a deferred task.
//
// This must be savable.
type TaskWorker interface {
	// TaskWork will be executed prior to returning to user space. Note that
	// TaskWork may call RegisterWork again, but this will not be executed until
	// the next return to user space, unlike in Linux. This effectively allows
	// registration of indefinite user return hooks, but not by default.
	TaskWork(t *Task)
}

// RegisterWork can be used to register additional task work that will be
// performed prior to returning to user space. See TaskWorker.TaskWork for
// semantics regarding registration.
func (t *Task) RegisterWork(work TaskWorker) {
	t.taskWorkMu.Lock()
	defer t.taskWorkMu.Unlock()
	t.taskWorkCount.Add(1)
	t.taskWork = append(t.taskWork, work)
}
