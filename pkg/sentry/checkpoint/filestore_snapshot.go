// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package checkpoint

import "os"

// FilestoreSnapshot identifies a private MemoryFile (by ResourceID) and the
// destination host file its backing file is FICLONE'd (reflink-cloned) to
// during a state checkpoint's freeze window. Taking the snapshot inside the
// window makes the filestore snapshot and the saved memory-state metadata
// describe the same instant, which is what allows the combination to remain
// correct with leave-running checkpoints.
//
// It is defined here (rather than in pkg/sentry/state) so that both
// pkg/sentry/kernel and pkg/sentry/state can use it without an import cycle.
type FilestoreSnapshot struct {
	// ID identifies the private MemoryFile to snapshot.
	ID ResourceID
	// Name is the artifact file name the destination will get in the
	// snapshot directory (e.g. "filestore-0"); it is recorded in the
	// filestores.json sidecar manifest.
	Name string
	// Dest is the (pre-created, empty) destination file for the reflink
	// clone. It lives on the same filesystem as the snapshot directory.
	Dest *os.File
}
