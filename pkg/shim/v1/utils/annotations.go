// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package utils

import (
	"path/filepath"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/runsc/specutils"
)

// Annotations from the CRI annotations package.
//
// These are vendor due to import conflicts.
const (
	sandboxLogDirAnnotation = "io.kubernetes.cri.sandbox-log-directory"
	sandboxUIDAnnotation    = "io.kubernetes.cri.sandbox-uid"
	// ContainerTypeAnnotation is they key that defines sandbox or container.
	ContainerTypeAnnotation = "io.kubernetes.cri.container-type"
	containerTypeSandbox    = "sandbox"
	// ContainerTypeContainer is the value for container.
	ContainerTypeContainer = "container"

	// FuseAbortOnTeardownAnnotation is the per-pod opt-in annotation to enable
	// reactive FUSE connection abort during container/sandbox teardown.
	FuseAbortOnTeardownAnnotation = "dev.gvisor.fuse.abort-on-teardown"
)

// FuseAbortOnTeardown checks whether the opt-in annotation is enabled on the spec,
// or on the pod sandbox spec if this is a workload container.
func FuseAbortOnTeardown(s *specs.Spec, bundle string) bool {
	if s == nil || s.Annotations == nil {
		return false
	}
	// Check the annotation on the spec itself.
	if s.Annotations[FuseAbortOnTeardownAnnotation] == "true" {
		return true
	}
	// Check the annotation on the pod sandbox spec.
	if bundle != "" {
		sandboxID := s.Annotations[specutils.ContainerdSandboxIDAnnotation]
		if sandboxID != "" {
			sandboxBundle := filepath.Join(filepath.Dir(bundle), sandboxID)
			if sandboxSpec, err := ReadSpec(sandboxBundle); err == nil && sandboxSpec.Annotations != nil {
				return sandboxSpec.Annotations[FuseAbortOnTeardownAnnotation] == "true"
			}
		}
	}
	return false
}
