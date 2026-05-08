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

package specutils

import (
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/runsc/config"
)

// HasRDMADevicesInSpec returns true if the OCI spec lists at least one
// /dev/infiniband/uverbs* device. Used to gate sysfs RDMA topology
// serialization at chroot time, so PCI/RDMA/NUMA snapshot data is only
// collected when the container actually requests RDMA devices.
//
// This intentionally does NOT consult the runtime rdmaproxy enable flag
// (which lives in the rdmaproxy package, downstream of this PR) — sysfs
// data collection is harmless without rdmaproxy and shipping serialize
// alone should not require rdmaproxy.
func HasRDMADevicesInSpec(spec *specs.Spec) bool {
	if spec.Linux == nil {
		return false
	}
	for _, dev := range spec.Linux.Devices {
		if strings.HasPrefix(dev.Path, "/dev/infiniband/uverbs") {
			return true
		}
	}
	return false
}

// AnnotationRDMAProxy enables rdmaproxy via OCI annotation as an alternative
// to the --rdmaproxy runtime flag. Useful when only some containers should
// use rdmaproxy on a runtime that otherwise has it disabled by default.
const AnnotationRDMAProxy = "dev.gvisor.internal.rdmaproxy"

// RDMAProxyEnabled returns true if rdmaproxy should be enabled for this
// container, either via the --rdmaproxy runtime flag or via the
// dev.gvisor.internal.rdmaproxy OCI annotation.
func RDMAProxyEnabled(spec *specs.Spec, conf *config.Config) bool {
	if conf.RDMAProxy {
		return true
	}
	return AnnotationToBool(spec, AnnotationRDMAProxy)
}

// RDMAFunctionalityRequested returns true if the container should have
// access to RDMA functionality. Requires both rdmaproxy to be enabled
// (via flag or annotation) AND at least one /dev/infiniband/uverbs*
// device to be present in the OCI spec.
func RDMAFunctionalityRequested(spec *specs.Spec, conf *config.Config) bool {
	if !RDMAProxyEnabled(spec, conf) {
		return false
	}
	return HasRDMADevicesInSpec(spec)
}
