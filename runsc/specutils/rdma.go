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

// AnnotationRDMAProxy enables rdmaproxy.
const AnnotationRDMAProxy = "dev.gvisor.internal.rdmaproxy"

// RDMAProxyEnabled checks both the rdmaproxy annotation and conf.RDMAProxy to
// see if rdmaproxy is enabled.
func RDMAProxyEnabled(spec *specs.Spec, conf *config.Config) bool {
	if conf.RDMAProxy {
		return true
	}
	return AnnotationToBool(spec, AnnotationRDMAProxy)
}

// RDMAFunctionalityRequested returns true if the container should have access
// to RDMA functionality. It requires rdmaproxy to be enabled runtime-wide and
// at least one /dev/infiniband/uverbs* device to be present in the OCI spec.
func RDMAFunctionalityRequested(spec *specs.Spec, conf *config.Config) bool {
	if !RDMAProxyEnabled(spec, conf) {
		return false
	}
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
