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

// Annotations from the CRI annotations package.
//
// These are vendor due to import conflicts.
const (
	sandboxLogDirAnnotation = "io.kubernetes.cri.sandbox-log-directory"
	// ContainerTypeAnnotation is they key that defines sandbox or container.
	ContainerTypeAnnotation = "io.kubernetes.cri.container-type"
	containerTypeSandbox    = "sandbox"
	// ContainerTypeContainer is the value for container.
	ContainerTypeContainer = "container"

	// Pod-level resource annotations set by the containerd CRI plugin on the
	// sandbox (pause) container's OCI config. Because gVisor collapses all
	// containers in a pod into a single sandbox process, the pod-level limits
	// carried in these annotations are the only ones that can meaningfully
	// bound the sandbox's host cgroup. See google/gvisor#13777.
	//
	// These match the constants in containerd's pkg/cri/annotations package
	// (SandboxCPUQuota / SandboxCPUPeriod / SandboxCPUShares / SandboxMem).
	// They are duplicated here (rather than imported) to avoid a heavy
	// dependency on containerd internals.
	SandboxCPUQuotaAnnotation  = "io.kubernetes.cri.sandbox-cpu-quota"
	SandboxCPUPeriodAnnotation = "io.kubernetes.cri.sandbox-cpu-period"
	SandboxCPUSharesAnnotation = "io.kubernetes.cri.sandbox-cpu-shares"
	SandboxMemoryAnnotation    = "io.kubernetes.cri.sandbox-memory"
)
