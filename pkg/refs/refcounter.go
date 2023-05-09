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

// Package refs defines an interface for reference counted objects.
package refs

import (
	"bytes"
	"fmt"
	"runtime"

	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sync"
)

// RefCounter is the interface to be implemented by objects that are reference
// counted.
type RefCounter interface {
	// IncRef increments the reference counter on the object.
	IncRef()

	// DecRef decrements the object's reference count. Users of refs_template.Refs
	// may specify a destructor to be called once the reference count reaches zero.
	DecRef(ctx context.Context)
}

// TryRefCounter is like RefCounter but allow the ref increment to be tried.
type TryRefCounter interface {
	RefCounter

	// TryIncRef attempts to increment the reference count, but may fail if all
	// references have already been dropped, in which case it returns false. If
	// true is returned, then a valid reference is now held on the object.
	TryIncRef() bool
}

// LeakMode configures the leak checker.
type LeakMode uint32

const (
	// NoLeakChecking indicates that no effort should be made to check for
	// leaks.
	NoLeakChecking LeakMode = iota

	// LeaksLogWarning indicates that a warning should be logged when leaks
	// are found.
	LeaksLogWarning

	// LeaksPanic indidcates that a panic should be issued when leaks are found.
	LeaksPanic
)

// Set implements flag.Value.
func (l *LeakMode) Set(v string) error {
	switch v {
	case "disabled":
		*l = NoLeakChecking
	case "log-names":
		*l = LeaksLogWarning
	case "panic":
		*l = LeaksPanic
	default:
		return fmt.Errorf("invalid ref leak mode %q", v)
	}
	return nil
}

// Get implements flag.Value.
func (l *LeakMode) Get() any {
	return *l
}

// String implements flag.Value.
func (l LeakMode) String() string {
	switch l {
	case NoLeakChecking:
		return "disabled"
	case LeaksLogWarning:
		return "log-names"
	case LeaksPanic:
		return "panic"
	default:
		panic(fmt.Sprintf("invalid ref leak mode %d", l))
	}
}

// leakMode stores the current mode for the reference leak checker.
//
// Values must be one of the LeakMode values.
//
// leakMode must be accessed atomically.
var leakMode atomicbitops.Uint32

// SetLeakMode configures the reference leak checker.
func SetLeakMode(mode LeakMode) {
	leakMode.Store(uint32(mode))
}

// GetLeakMode returns the current leak mode.
func GetLeakMode() LeakMode {
	return LeakMode(leakMode.Load())
}

const maxStackFrames = 40

type fileLine struct {
	file string
	line int
}

// A stackKey is a representation of a stack frame for use as a map key.
//
// The fileLine type is used as PC values seem to vary across collections, even
// for the same call stack.
type stackKey [maxStackFrames]fileLine

var stackCache = struct {
	sync.Mutex
	entries map[stackKey][]uintptr
}{entries: map[stackKey][]uintptr{}}

func makeStackKey(pcs []uintptr) stackKey {
	frames := runtime.CallersFrames(pcs)
	var key stackKey
	keySlice := key[:0]
	for {
		frame, more := frames.Next()
		keySlice = append(keySlice, fileLine{frame.File, frame.Line})

		if !more || len(keySlice) == len(key) {
			break
		}
	}
	return key
}

// RecordStack constructs and returns the PCs on the current stack.
func RecordStack() []uintptr {
	pcs := make([]uintptr, maxStackFrames)
	n := runtime.Callers(1, pcs)
	if n == 0 {
		// No pcs available. Stop now.
		//
		// This can happen if the first argument to runtime.Callers
		// is large.
		return nil
	}
	pcs = pcs[:n]
	key := makeStackKey(pcs)
	stackCache.Lock()
	v, ok := stackCache.entries[key]
	if !ok {
		// Reallocate to prevent pcs from escaping.
		v = append([]uintptr(nil), pcs...)
		stackCache.entries[key] = v
	}
	stackCache.Unlock()
	return v
}

// FormatStack converts the given stack into a readable format.
func FormatStack(pcs []uintptr) string {
	frames := runtime.CallersFrames(pcs)
	var trace bytes.Buffer
	for {
		frame, more := frames.Next()
		fmt.Fprintf(&trace, "%s:%d: %s\n", frame.File, frame.Line, frame.Function)

		if !more {
			break
		}
	}
	return trace.String()
}

// OnExit is called on sandbox exit. It runs GC to enqueue refcount finalizers,
// which check for reference leaks. There is no way to guarantee that every
// finalizer will run before exiting, but this at least ensures that they will
// be discovered/enqueued by GC.
func OnExit() {
	if LeakMode(leakMode.Load()) != NoLeakChecking {
		runtime.GC()
	}
}
