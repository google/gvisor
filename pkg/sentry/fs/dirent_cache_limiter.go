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

package fs

import (
	"fmt"
	"sync"
)

// DirentCacheLimiter acts as a global limit for all dirent caches in the
// process.
//
// +stateify savable
type DirentCacheLimiter struct {
	mu    sync.Mutex `state:"nosave"`
	max   uint64
	count uint64 `state:"zerovalue"`
}

// NewDirentCacheLimiter creates a new DirentCacheLimiter.
func NewDirentCacheLimiter(max uint64) *DirentCacheLimiter {
	return &DirentCacheLimiter{max: max}
}

func (d *DirentCacheLimiter) tryInc() bool {
	d.mu.Lock()
	if d.count >= d.max {
		d.mu.Unlock()
		return false
	}
	d.count++
	d.mu.Unlock()
	return true
}

func (d *DirentCacheLimiter) dec() {
	d.mu.Lock()
	if d.count == 0 {
		panic(fmt.Sprintf("underflowing DirentCacheLimiter count: %+v", d))
	}
	d.count--
	d.mu.Unlock()
}
