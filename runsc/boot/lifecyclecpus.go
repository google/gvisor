// Copyright 2026 The gVisor Authors.
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

package boot

import (
	"gvisor.dev/gvisor/pkg/gomaxprocs"
	"gvisor.dev/gvisor/pkg/sync"
)

// maxLifecycleProcs is the maximum number of temporary GOMAXPROCS that
// lifecycleCPUs adds.
const maxLifecycleProcs = 12

// lifecycleCPUs lets `checkpoint` and `restore` use the CPUs of the
// sandbox's lifecycle CPU limit.
// It temporarily bumps GOMAXPROCS while they run.
type lifecycleCPUs struct {
	// num is the number of CPUs that checkpoint and restore can use.
	// Immutable after init.
	num int

	// procs is the number of temporary GOMAXPROCS to add.
	// Immutable after init.
	procs int

	mu sync.Mutex

	// holds is the number of holds on the temporary GOMAXPROCS.
	//
	// +checklocks:mu
	holds int

	// restoring is true while restore holds the temporary GOMAXPROCS.
	//
	// +checklocks:mu
	restoring bool
}

// init sets the CPUs that checkpoint and restore can use, given `num` CPUs
// under the lifecycle CPU limit and `base` GOMAXPROCS.
func (c *lifecycleCPUs) init(num, base int) {
	c.num = max(num, base)
	c.procs = min(c.num-base, maxLifecycleProcs)
}

// hold adds the temporary GOMAXPROCS until a matching call to release.
func (c *lifecycleCPUs) hold() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.holdLocked()
}

// release undoes a call to hold.
func (c *lifecycleCPUs) release() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.releaseLocked()
}

// holdForRestore adds the temporary GOMAXPROCS until releaseForRestore.
// No-op if restore already holds them.
func (c *lifecycleCPUs) holdForRestore() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.restoring {
		c.restoring = true
		c.holdLocked()
	}
}

// releaseForRestore undoes holdForRestore.
// No-op if restore does not hold the temporary GOMAXPROCS.
func (c *lifecycleCPUs) releaseForRestore() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.restoring {
		c.restoring = false
		c.releaseLocked()
	}
}

// +checklocks:c.mu
func (c *lifecycleCPUs) holdLocked() {
	if c.holds == 0 {
		gomaxprocs.Add(c.procs)
	}
	c.holds++
}

// +checklocks:c.mu
func (c *lifecycleCPUs) releaseLocked() {
	c.holds--
	if c.holds == 0 {
		gomaxprocs.Add(-c.procs)
	}
}
