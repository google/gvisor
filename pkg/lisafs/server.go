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
	"gvisor.dev/gvisor/pkg/sync"
)

// Server serves a filesystem tree.
type Server struct {
	// RenameMu synchronizes rename operations within this filesystem tree.
	RenameMu sync.RWMutex

	// mountPath represents the host path at which this server is mounted.
	// mountPath is immutable.
	mountPath string
}

func newServer(mountPath string) *Server {
	return &Server{
		mountPath: mountPath,
	}
}

// MountPath returns the host path at which this server is mounted.
func (s *Server) MountPath() string {
	return s.mountPath
}
