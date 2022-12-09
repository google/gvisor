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

package refs

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sync"
)

var (
	// liveObjects is a global map of reference-counted objects. Objects are
	// inserted when leak check is enabled, and they are removed when they are
	// destroyed. It is protected by liveObjectsMu.
	liveObjects   map[CheckedObject]struct{}
	liveObjectsMu sync.Mutex
)

// CheckedObject represents a reference-counted object with an informative
// leak detection message.
type CheckedObject interface {
	// RefType is the type of the reference-counted object.
	RefType() string

	// LeakMessage supplies a warning to be printed upon leak detection.
	LeakMessage() string

	// LogRefs indicates whether reference-related events should be logged.
	LogRefs() bool
}

func init() {
	liveObjects = make(map[CheckedObject]struct{})
}

// LeakCheckEnabled returns whether leak checking is enabled. The following
// functions should only be called if it returns true.
func LeakCheckEnabled() bool {
	mode := GetLeakMode()
	return mode != NoLeakChecking
}

// leakCheckPanicEnabled returns whether DoLeakCheck() should panic when leaks
// are detected.
func leakCheckPanicEnabled() bool {
	return GetLeakMode() == LeaksPanic
}

// Register adds obj to the live object map.
func Register(obj CheckedObject) {
	if LeakCheckEnabled() {
		liveObjectsMu.Lock()
		if _, ok := liveObjects[obj]; ok {
			panic(fmt.Sprintf("Unexpected entry in leak checking map: reference %p already added", obj))
		}
		liveObjects[obj] = struct{}{}
		liveObjectsMu.Unlock()
		if LeakCheckEnabled() && obj.LogRefs() {
			logEvent(obj, "registered")
		}
	}
}

// Unregister removes obj from the live object map.
func Unregister(obj CheckedObject) {
	if LeakCheckEnabled() {
		liveObjectsMu.Lock()
		defer liveObjectsMu.Unlock()
		if _, ok := liveObjects[obj]; !ok {
			panic(fmt.Sprintf("Expected to find entry in leak checking map for reference %p", obj))
		}
		delete(liveObjects, obj)
		if LeakCheckEnabled() && obj.LogRefs() {
			logEvent(obj, "unregistered")
		}
	}
}

// LogIncRef logs a reference increment.
func LogIncRef(obj CheckedObject, refs int64) {
	if LeakCheckEnabled() && obj.LogRefs() {
		logEvent(obj, fmt.Sprintf("IncRef to %d", refs))
	}
}

// LogTryIncRef logs a successful TryIncRef call.
func LogTryIncRef(obj CheckedObject, refs int64) {
	if LeakCheckEnabled() && obj.LogRefs() {
		logEvent(obj, fmt.Sprintf("TryIncRef to %d", refs))
	}
}

// LogDecRef logs a reference decrement.
func LogDecRef(obj CheckedObject, refs int64) {
	if LeakCheckEnabled() && obj.LogRefs() {
		logEvent(obj, fmt.Sprintf("DecRef to %d", refs))
	}
}

// logEvent logs a message for the given reference-counted object.
//
// obj.LogRefs() should be checked before calling logEvent, in order to avoid
// calling any text processing needed to evaluate msg.
func logEvent(obj CheckedObject, msg string) {
	log.Infof("[%s %p] %s:\n%s", obj.RefType(), obj, msg, FormatStack(RecordStack()))
}

// checkOnce makes sure that leak checking is only done once. DoLeakCheck is
// called from multiple places (which may overlap) to cover different sandbox
// exit scenarios.
var checkOnce sync.Once

// DoLeakCheck iterates through the live object map and logs a message for each
// object. It should be called when no reference-counted objects are reachable
// anymore, at which point anything left in the map is considered a leak. On
// multiple calls, only the first call will perform the leak check.
func DoLeakCheck() {
	if LeakCheckEnabled() {
		checkOnce.Do(doLeakCheck)
	}
}

// DoRepeatedLeakCheck is the same as DoLeakCheck except that it can be called
// multiple times by the caller to incrementally perform leak checking.
func DoRepeatedLeakCheck() {
	if LeakCheckEnabled() {
		doLeakCheck()
	}
}

type leakCheckDisabled interface {
	LeakCheckDisabled() bool
}

// CleanupSync is used to wait for async cleanup actions.
var CleanupSync sync.WaitGroup

func doLeakCheck() {
	CleanupSync.Wait()
	liveObjectsMu.Lock()
	defer liveObjectsMu.Unlock()
	leaked := len(liveObjects)
	if leaked > 0 {
		n := 0
		msg := fmt.Sprintf("Leak checking detected %d leaked objects:\n", leaked)
		for obj := range liveObjects {
			skip := false
			if o, ok := obj.(leakCheckDisabled); ok {
				skip = o.LeakCheckDisabled()
			}
			if skip {
				log.Debugf(obj.LeakMessage())
				continue
			}
			msg += obj.LeakMessage() + "\n"
			n++
		}
		if n == 0 {
			return
		}
		if leakCheckPanicEnabled() {
			panic(msg)
		}
		log.Warningf(msg)
	}
}
