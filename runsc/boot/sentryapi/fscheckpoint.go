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
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/runsc/specutils"
)

const (
	AnnotationFSCheckpointPrefix = "dev.gvisor.internal.fscheckpoint."

	// AnnotationFSCheckpointPath is the path to the directory where the
	// filesystem checkpoint files will be created. When present, it allows for
	// the workload running inside to trigger a filesystem checkpoint without
	// having to use the runsc CLI.
	AnnotationFSCheckpointPath = AnnotationFSCheckpointPrefix + "path"

	// AnnotationFSCheckpointDirect indicates whether filesystem checkpoint
	// I/Os triggered via /proc/gvisor should use O_DIRECT. Optional, defaults
	// to false.
	AnnotationFSCheckpointDirect = AnnotationFSCheckpointPrefix + "direct"

	// AnnotationFSCheckpointPaths is a comma-separated list of paths inside the
	// containers to save. Optional.
	AnnotationFSCheckpointPaths = AnnotationFSCheckpointPrefix + "paths"
)

// GetAnnotationFSCheckpointPath returns the filesystem checkpoint path
// specified in the container annotation. Return empty string if no annotation
// is specified.
func GetAnnotationFSCheckpointPath(spec *specs.Spec) string {
	return spec.Annotations[AnnotationFSCheckpointPath]
}

// GetAnnotationFSCheckpointDirect returns true if filesystem checkpoint I/O
// controlled by the containing annotation should use O_DIRECT.
func GetAnnotationFSCheckpointDirect(spec *specs.Spec) bool {
	return specutils.AnnotationToBool(spec, AnnotationFSCheckpointDirect)
}

// GetAnnotationFSCheckpointPaths returns the filesystem checkpoint target paths
// specified in the container annotation.
func GetAnnotationFSCheckpointPaths(spec *specs.Spec) []string {
	annot := spec.Annotations[AnnotationFSCheckpointPaths]
	if annot == "" {
		return nil
	}
	return strings.Split(annot, ",")
}
