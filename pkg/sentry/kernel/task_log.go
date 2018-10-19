// Copyright 2018 Google LLC
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
	"sort"

	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
)

const (
	// maxStackDebugBytes is the maximum number of user stack bytes that may be
	// printed by debugDumpStack.
	maxStackDebugBytes = 1024
)

// Infof logs an formatted info message by calling log.Infof.
func (t *Task) Infof(fmt string, v ...interface{}) {
	if log.IsLogging(log.Info) {
		log.Infof(t.logPrefix.Load().(string)+fmt, v...)
	}
}

// Warningf logs a warning string by calling log.Warningf.
func (t *Task) Warningf(fmt string, v ...interface{}) {
	if log.IsLogging(log.Warning) {
		log.Warningf(t.logPrefix.Load().(string)+fmt, v...)
	}
}

// Debugf creates a debug string that includes the task ID.
func (t *Task) Debugf(fmt string, v ...interface{}) {
	if log.IsLogging(log.Debug) {
		log.Debugf(t.logPrefix.Load().(string)+fmt, v...)
	}
}

// IsLogging returns true iff this level is being logged.
func (t *Task) IsLogging(level log.Level) bool {
	return log.IsLogging(level)
}

// DebugDumpState logs task state at log level debug.
//
// Preconditions: The caller must be running on the task goroutine.
func (t *Task) DebugDumpState() {
	t.debugDumpRegisters()
	t.debugDumpStack()
	if mm := t.MemoryManager(); mm != nil {
		t.Debugf("Mappings:\n%s", mm)
	}
	t.Debugf("FDMap:\n%s", t.fds)
}

// debugDumpRegisters logs register state at log level debug.
//
// Preconditions: The caller must be running on the task goroutine.
func (t *Task) debugDumpRegisters() {
	if !t.IsLogging(log.Debug) {
		return
	}
	regmap, err := t.Arch().RegisterMap()
	if err != nil {
		t.Debugf("Registers: %v", err)
	} else {
		t.Debugf("Registers:")
		var regs []string
		for reg := range regmap {
			regs = append(regs, reg)
		}
		sort.Strings(regs)
		for _, reg := range regs {
			t.Debugf("%-8s = %016x", reg, regmap[reg])
		}
	}
}

// debugDumpStack logs user stack contents at log level debug.
//
// Preconditions: The caller must be running on the task goroutine.
func (t *Task) debugDumpStack() {
	if !t.IsLogging(log.Debug) {
		return
	}
	m := t.MemoryManager()
	if m == nil {
		t.Debugf("Memory manager for task is gone, skipping application stack dump.")
		return
	}
	t.Debugf("Stack:")
	start := usermem.Addr(t.Arch().Stack())
	// Round addr down to a 16-byte boundary.
	start &= ^usermem.Addr(15)
	// Print 16 bytes per line, one byte at a time.
	for offset := uint64(0); offset < maxStackDebugBytes; offset += 16 {
		addr, ok := start.AddLength(offset)
		if !ok {
			break
		}
		var data [16]byte
		n, err := m.CopyIn(t, addr, data[:], usermem.IOOpts{
			IgnorePermissions: true,
		})
		// Print as much of the line as we can, even if an error was
		// encountered.
		if n > 0 {
			t.Debugf("%x: % x", addr, data[:n])
		}
		if err != nil {
			t.Debugf("Error reading stack at address %x: %v", addr+usermem.Addr(n), err)
			break
		}
	}
}

// updateLogPrefix updates the task's cached log prefix to reflect its
// current thread ID.
//
// Preconditions: The task's owning TaskSet.mu must be locked.
func (t *Task) updateLogPrefixLocked() {
	// Use the task's TID in the root PID namespace for logging.
	t.logPrefix.Store(fmt.Sprintf("[% 4d] ", t.tg.pidns.owner.Root.tids[t]))
}
