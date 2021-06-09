// Copyright 2021 The gVisor Authors.
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

package lisafs

import (
	"gvisor.dev/gvisor/pkg/refsvfs2"
)

// FDID (file descriptor identifier) is used to identify FDs on a connection.
// Each connection has its own FDID namespace.
//
// +marshal slice:FDIDSlice
type FDID uint32

// InvalidFDID represents an invalid FDID.
const InvalidFDID FDID = 0

// Ok returns true if f is a valid FDID.
func (f FDID) Ok() bool {
	return f != InvalidFDID
}

// FD represents a file descriptor on the host filesystem. This is the main
// gateway to perform actions on the backing filesystem. This interface should
// remain minimal. Server implementations can extend this as needed.
type FD interface {
	refsvfs2.RefCounter
}
