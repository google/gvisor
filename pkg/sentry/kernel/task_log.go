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

package kernel

import (
	"fmt"
	"runtime/trace"
	"sort"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/usermem"
)

const (
	// maxStackDebugBytes is the maximum number of user stack bytes that may be
	// printed by debugDumpStack.
	maxStackDebugBytes = 1024
	// maxCodeDebugBytes is the maximum number of user code bytes that may be
	// printed by debugDumpCode.
	maxCodeDebugBytes = 128
)

// Infof logs an formatted info message by calling log.Infof.
func (t *Task) Infof(fmt string, v ...interface{}) {
	if log.IsLogging(log.Info) {
		log.InfofAtDepth(1, t.logPrefix.Load().(string)+fmt, v...)
	}
}

// Warningf logs a warning string by calling log.Warningf.
func (t *Task) Warningf(fmt string, v ...interface{}) {
	if log.IsLogging(log.Warning) {
		log.WarningfAtDepth(1, t.logPrefix.Load().(string)+fmt, v...)
	}
}

// Debugf creates a debug string that includes the task ID.
func (t *Task) Debugf(fmt string, v ...interface{}) {
	if log.IsLogging(log.Debug) {
		log.DebugfAtDepth(1, t.logPrefix.Load().(string)+fmt, v...)
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
	t.debugDumpCode()
	if mm := t.MemoryManager(); mm != nil {
		t.Debugf("Mappings:\n%s", mm)
	}
	t.Debugf("FDTable:\n%s", t.fdTable)
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
	start := hostarch.Addr(t.Arch().Stack())
	// Round addr down to a 16-byte boundary.
	start &= ^hostarch.Addr(15)
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
			t.Debugf("Error reading stack at address %x: %v", addr+hostarch.Addr(n), err)
			break
		}
	}
}

// debugDumpCode logs user code contents at log level debug.
//
// Preconditions: The caller must be running on the task goroutine.
func (t *Task) debugDumpCode() {
	if !t.IsLogging(log.Debug) {
		return
	}
	m := t.MemoryManager()
	if m == nil {
		t.Debugf("Memory manager for task is gone, skipping application code dump.")
		return
	}
	t.Debugf("Code:")
	// Print code on both sides of the instruction register.
	start := hostarch.Addr(t.Arch().IP()) - maxCodeDebugBytes/2
	// Round addr down to a 16-byte boundary.
	start &= ^hostarch.Addr(15)
	// Print 16 bytes per line, one byte at a time.
	for offset := uint64(0); offset < maxCodeDebugBytes; offset += 16 {
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
			t.Debugf("Error reading stack at address %x: %v", addr+hostarch.Addr(n), err)
			break
		}
	}
}

// trace definitions.
//
// Note that all region names are prefixed by ':' in order to ensure that they
// are lexically ordered before all system calls, which use the naked system
// call name (e.g. "read") for maximum clarity.
const (
	traceCategory = "task"
	runRegion     = ":run"
	blockRegion   = ":block"
	cpuidRegion   = ":cpuid"
	faultRegion   = ":fault"
)

// updateInfoLocked updates the task's cached log prefix and tracing
// information to reflect its current thread ID.
//
// Preconditions: The task's owning TaskSet.mu must be locked.
func (t *Task) updateInfoLocked() {
	// Use the task's TID in the root PID namespace for logging.
	tid := t.tg.pidns.owner.Root.tids[t]
	t.logPrefix.Store(fmt.Sprintf("[% 4d] ", tid))
	t.rebuildTraceContext(tid)
}

// rebuildTraceContext rebuilds the trace context.
//
// Precondition: the passed tid must be the tid in the root namespace.
func (t *Task) rebuildTraceContext(tid ThreadID) {
	// Re-initialize the trace context.
	if t.traceTask != nil {
		t.traceTask.End()
	}

	// Note that we define the "task type" to be the dynamic TID. This does
	// not align perfectly with the documentation for "tasks" in the
	// tracing package. Tasks may be assumed to be bounded by analysis
	// tools. However, if we just use a generic "task" type here, then the
	// "user-defined tasks" page on the tracing dashboard becomes nearly
	// unusable, as it loads all traces from all tasks.
	//
	// We can assume that the number of tasks in the system is not
	// arbitrarily large (in general it won't be, especially for cases
	// where we're collecting a brief profile), so using the TID is a
	// reasonable compromise in this case.
	t.traceContext, t.traceTask = trace.NewTask(context.Background(), fmt.Sprintf("tid:%d", tid))
}

// traceCloneEvent is called when a new task is spawned.
//
// ntid must be the new task's ThreadID in the root namespace.
func (t *Task) traceCloneEvent(ntid ThreadID) {
	if !trace.IsEnabled() {
		return
	}
	trace.Logf(t.traceContext, traceCategory, "spawn: %d", ntid)
}

// traceExitEvent is called when a task exits.
func (t *Task) traceExitEvent() {
	if !trace.IsEnabled() {
		return
	}
	trace.Logf(t.traceContext, traceCategory, "exit status: 0x%x", t.exitStatus.Status())
}

// traceExecEvent is called when a task calls exec.
func (t *Task) traceExecEvent(image *TaskImage) {
	if !trace.IsEnabled() {
		return
	}
	file := image.MemoryManager.Executable()
	if file == nil {
		trace.Logf(t.traceContext, traceCategory, "exec: << unknown >>")
		return
	}
	defer file.DecRef(t)
	trace.Logf(t.traceContext, traceCategory, "exec: %s", file.PathnameWithDeleted(t))
}
