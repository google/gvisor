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

import (
	"gvisor.dev/gvisor/pkg/context"
)

// AIOCallback is an function that does asynchronous I/O on behalf of a task.
type AIOCallback func(context.Context)

// QueueAIO queues an AIOCallback which will be run asynchronously.
func (t *Task) QueueAIO(cb AIOCallback) {
	ctx := t.AsyncContext()
	wg := &t.TaskSet().aioGoroutines
	wg.Add(1)
	go func() {
		cb(ctx)
		wg.Done()
	}()
}
