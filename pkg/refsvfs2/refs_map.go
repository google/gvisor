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

package refsvfs2

import (
	"fmt"
	"strings"

	"gvisor.dev/gvisor/pkg/log"
	refs_vfs1 "gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/sync"
)

// TODO(gvisor.dev/issue/1193): re-enable once kernfs refs are fixed.
var ignored []string = []string{"kernfs.", "proc.", "sys.", "devpts.", "fuse."}

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
	// LeakMessage supplies a warning to be printed upon leak detection.
	LeakMessage() string
}

func init() {
	liveObjects = make(map[CheckedObject]struct{})
}

// LeakCheckEnabled returns whether leak checking is enabled. The following
// functions should only be called if it returns true.
func LeakCheckEnabled() bool {
	return refs_vfs1.GetLeakMode() != refs_vfs1.NoLeakChecking
}

// Register adds obj to the live object map.
func Register(obj CheckedObject, typ string) {
	for _, str := range ignored {
		if strings.Contains(typ, str) {
			return
		}
	}
	liveObjectsMu.Lock()
	if _, ok := liveObjects[obj]; ok {
		panic(fmt.Sprintf("Unexpected entry in leak checking map: reference %p already added", obj))
	}
	liveObjects[obj] = struct{}{}
	liveObjectsMu.Unlock()
}

// Unregister removes obj from the live object map.
func Unregister(obj CheckedObject, typ string) {
	liveObjectsMu.Lock()
	defer liveObjectsMu.Unlock()
	if _, ok := liveObjects[obj]; !ok {
		for _, str := range ignored {
			if strings.Contains(typ, str) {
				return
			}
		}
		panic(fmt.Sprintf("Expected to find entry in leak checking map for reference %p", obj))
	}
	delete(liveObjects, obj)
}

// DoLeakCheck iterates through the live object map and logs a message for each
// object. It is called once no reference-counted objects should be reachable
// anymore, at which point anything left in the map is considered a leak.
func DoLeakCheck() {
	liveObjectsMu.Lock()
	defer liveObjectsMu.Unlock()
	leaked := len(liveObjects)
	if leaked > 0 {
		log.Warningf("Leak checking detected %d leaked objects:", leaked)
		for obj := range liveObjects {
			log.Warningf(obj.LeakMessage())
		}
	}
}
