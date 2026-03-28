// Copyright 2026 The gVisor Authors.
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

// Package checkpoint defines types that are used by multiple forms of gVisor
// checkpoints.
package checkpoint

import (
	"fmt"
)

// ResourceID is a unique ID that is used to identify resources between save/restore sessions.
// Examples of resources are host files, gofer connection for mount points, etc.
//
// +stateify savable
type ResourceID struct {
	// ContainerName is the name of the container that the resource belongs to.
	ContainerName string `json:"container_name"`
	// Path is the path of the resource. Path is never empty for a valid
	// ResourceID.
	Path string `json:"path"`
}

// Ok returns true if the ResourceID is valid and not the zero value.
func (id ResourceID) Ok() bool {
	return id.Path != ""
}

func (id ResourceID) String() string {
	return fmt.Sprintf("%s:%s", id.ContainerName, id.Path)
}
