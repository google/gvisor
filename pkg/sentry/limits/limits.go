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

// Package limits provides resource limits.
package limits

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/sync"
)

// LimitType defines a type of resource limit.
type LimitType int

// Set of constants defining the different types of resource limits.
const (
	CPU LimitType = iota
	FileSize
	Data
	Stack
	Core
	Rss
	ProcessCount
	NumberOfFiles
	MemoryLocked
	AS
	Locks
	SignalsPending
	MessageQueueBytes
	Nice
	RealTimePriority
	Rttime
)

// AllLimitTypes contains all types in the order how they are presented in
// /proc/pid/limits.
var AllLimitTypes = []LimitType{
	CPU,
	FileSize,
	Data,
	Stack,
	Core,
	Rss,
	ProcessCount,
	NumberOfFiles,
	MemoryLocked,
	AS,
	Locks,
	SignalsPending,
	MessageQueueBytes,
	Nice,
	RealTimePriority,
	Rttime,
}

// Name returns the kernel name of the limit
func (lt LimitType) Name() string {
	switch lt {
	case CPU:
		return "Max cpu time"
	case FileSize:
		return "Max file size"
	case Data:
		return "Max data size"
	case Stack:
		return "Max stack size"
	case Core:
		return "Max core file size"
	case Rss:
		return "Max resident set"
	case ProcessCount:
		return "Max processes"
	case NumberOfFiles:
		return "Max open files"
	case MemoryLocked:
		return "Max locked memory"
	case AS:
		return "Max address space"
	case Locks:
		return "Max file locks"
	case SignalsPending:
		return "Max pending signals"
	case MessageQueueBytes:
		return "Max msgqueue size"
	case Nice:
		return "Max nice priority"
	case RealTimePriority:
		return "Max realtime priority"
	case Rttime:
		return "Max realtime timeout"
	}
	return "unknown"
}

// Unit returns the unit string for a limit
func (lt LimitType) Unit() string {
	switch lt {
	case CPU:
		return "seconds"
	case FileSize:
		return "bytes"
	case Data:
		return "bytes"
	case Stack:
		return "bytes"
	case Core:
		return "bytes"
	case Rss:
		return "bytes"
	case ProcessCount:
		return "processes"
	case NumberOfFiles:
		return "files"
	case MemoryLocked:
		return "bytes"
	case AS:
		return "bytes"
	case Locks:
		return "locks"
	case SignalsPending:
		return "signals"
	case MessageQueueBytes:
		return "bytes"
	case Nice:
		return ""
	case RealTimePriority:
		return ""
	case Rttime:
		return "us"
	}
	return ""
}

// Infinity is a constant representing a resource with no limit.
const Infinity = ^uint64(0)

// Limit specifies a system limit.
//
// +stateify savable
type Limit struct {
	// Cur specifies the current limit.
	Cur uint64 `json:"cur,omitempty"`
	// Max specifies the maximum settable limit.
	Max uint64 `json:"max,omitempty"`
}

// LimitSet represents the Limits that correspond to each LimitType.
//
// +stateify savable
type LimitSet struct {
	mu   sync.Mutex `state:"nosave"`
	data map[LimitType]Limit
}

// NewLimitSet creates a new, empty LimitSet.
func NewLimitSet() *LimitSet {
	return &LimitSet{
		data: make(map[LimitType]Limit),
	}
}

// GetCopy returns a clone of the LimitSet.
func (l *LimitSet) GetCopy() *LimitSet {
	l.mu.Lock()
	defer l.mu.Unlock()
	copyData := make(map[LimitType]Limit)
	for k, v := range l.data {
		copyData[k] = v
	}
	return &LimitSet{
		data: copyData,
	}
}

// Get returns the resource limit associated with LimitType t.
// If no limit is provided, it defaults to an infinite limit.Infinity.
func (l *LimitSet) Get(t LimitType) Limit {
	l.mu.Lock()
	defer l.mu.Unlock()
	s, ok := l.data[t]
	if !ok {
		return Limit{Cur: Infinity, Max: Infinity}
	}
	return s
}

// GetCapped returns the current value for the limit, capped as specified.
func (l *LimitSet) GetCapped(t LimitType, max uint64) uint64 {
	s := l.Get(t)
	if s.Cur == Infinity || s.Cur > max {
		return max
	}
	return s.Cur
}

// SetUnchecked assigns value v to resource of LimitType t.
func (l *LimitSet) SetUnchecked(t LimitType, v Limit) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.data[t] = v
}

// Set assigns value v to resource of LimitType t and returns the old value.
// privileged should be true only when either the caller has CAP_SYS_RESOURCE
// or when creating limits for a new kernel.
func (l *LimitSet) Set(t LimitType, v Limit, privileged bool) (Limit, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// If a limit is already set, make sure the new limit doesn't
	// exceed the previous max limit.
	if _, ok := l.data[t]; ok {
		// Unprivileged users can only lower their hard limits.
		if l.data[t].Max < v.Max && !privileged {
			return Limit{}, unix.EPERM
		}
		if v.Cur > v.Max {
			return Limit{}, unix.EINVAL
		}
	}
	old := l.data[t]
	l.data[t] = v
	return old, nil
}
