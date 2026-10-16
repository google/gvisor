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

package sentryapi

import (
	"path"

	"gvisor.dev/gvisor/pkg/fsutil"
)

// Supported filesystems that map to different internal filesystems.
const (
	Bind   = "bind"
	Nonefs = "none"
)

// SelfFilestorePath returns the path at which the self filestore file is
// stored for a given mount.
func SelfFilestorePath(mountSrc, sandboxID string) string {
	// We will place the filestore file in a gVisor specific hidden file inside
	// the mount being overlaid itself. The same volume can be overlaid by
	// multiple sandboxes. So make the filestore file unique to a sandbox by
	// suffixing the sandbox ID.
	return path.Join(mountSrc, selfFilestoreName(sandboxID))
}

// SelfFilestoreName returns the name of the self filestore file for a given sandbox.
func SelfFilestoreName(sandboxID string) string {
	return selfFilestoreName(sandboxID)
}

func selfFilestoreName(sandboxID string) string {
	return fsutil.SelfFilestorePrefix + sandboxID
}
