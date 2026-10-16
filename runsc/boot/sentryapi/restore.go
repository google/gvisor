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
	"fmt"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/state/statefile"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/specutils"
)

const (
	AnnotationCheckpointPrefix = "dev.gvisor.internal.checkpoint."

	// AnnotationCheckpointPath is the path to the directory where the checkpoint files will be
	// created. When present, it allows for the workload running inside to trigger a checkpoint
	// without having to use the runsc CLI.
	AnnotationCheckpointPath = AnnotationCheckpointPrefix + "path"

	// AnnotationCheckpointCompression is the compression to use for the checkpoint file. Optional,
	// defaults to best speed compression.
	AnnotationCheckpointCompression = AnnotationCheckpointPrefix + "compression"

	// AnnotationCheckpointDirect indicates whether the checkpoint IOs should use O_DIRECT. Optional,
	// defaults to false.
	AnnotationCheckpointDirect = AnnotationCheckpointPrefix + "direct"
)

// GetAnnotationCheckpointPath returns the checkpoint path specified in the
// container annotation. Return empty string if no annotation is specified.
func GetAnnotationCheckpointPath(conf *config.Config, spec *specs.Spec) (string, error) {
	path := spec.Annotations[AnnotationCheckpointPath]
	if len(path) != 0 {
		if len(conf.TestOnlyAutosaveImagePath) != 0 {
			return "", fmt.Errorf("autosave is not supported with %q annotation", AnnotationCheckpointPath)
		}
	}
	return path, nil
}

// GetAnnotationCheckpointCompression returns the checkpoint compression level
// specified in the container annotation.
func GetAnnotationCheckpointCompression(spec *specs.Spec) (statefile.CompressionLevel, error) {
	return statefile.CompressionLevelFromString(spec.Annotations[AnnotationCheckpointCompression])
}

// GetAnnotationCheckpointDirect returns true if the checkpoint is direct.
func GetAnnotationCheckpointDirect(spec *specs.Spec) bool {
	return specutils.AnnotationToBool(spec, AnnotationCheckpointDirect)
}
