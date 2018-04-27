// Copyright 2018 Google Inc.
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
	"sync"
)

// RestoreEnvironment is the restore environment for file systems. It consists
// of things that change across save and restore and therefore cannot be saved
// in the object graph.
type RestoreEnvironment struct {
	// MountSources maps Filesystem.Name() to mount arguments.
	MountSources map[string][]MountArgs

	// ValidateFileSize indicates file size should not change across S/R.
	ValidateFileSize bool

	// ValidateFileTimestamp indicates file modification timestamp should
	// not change across S/R.
	ValidateFileTimestamp bool
}

// MountArgs holds arguments to Mount.
type MountArgs struct {
	// Dev corresponds to the devname argumnent of Mount.
	Dev string

	// Flags corresponds to the flags argument of Mount.
	Flags MountSourceFlags

	// Data corresponds to the data argument of Mount.
	Data string
}

// restoreEnv holds the fs package global RestoreEnvironment.
var restoreEnv = struct {
	mu  sync.Mutex
	env RestoreEnvironment
	set bool
}{}

// SetRestoreEnvironment sets the RestoreEnvironment. Must be called before
// state.Load and only once.
func SetRestoreEnvironment(r RestoreEnvironment) {
	restoreEnv.mu.Lock()
	defer restoreEnv.mu.Unlock()
	if restoreEnv.set {
		panic("RestoreEnvironment may only be set once")
	}
	restoreEnv.env = r
	restoreEnv.set = true
}

// CurrentRestoreEnvironment returns the current, read-only RestoreEnvironment.
// If no RestoreEnvironment was ever set, returns (_, false).
func CurrentRestoreEnvironment() (RestoreEnvironment, bool) {
	restoreEnv.mu.Lock()
	defer restoreEnv.mu.Unlock()
	e := restoreEnv.env
	set := restoreEnv.set
	return e, set
}
