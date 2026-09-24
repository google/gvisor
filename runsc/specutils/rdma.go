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
	"path"
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/rdma"
	"gvisor.dev/gvisor/runsc/config"
)

// UverbsDevicesInSpec returns the /dev/infiniband/uverbs* devices listed in
// the OCI spec, in spec order.
func UverbsDevicesInSpec(spec *specs.Spec) []rdma.UverbsSpec {
	if spec.Linux == nil {
		return nil
	}
	var out []rdma.UverbsSpec
	for _, dev := range spec.Linux.Devices {
		if !strings.HasPrefix(dev.Path, "/dev/infiniband/uverbs") {
			continue
		}
		out = append(out, rdma.UverbsSpec{
			Name:  path.Base(dev.Path),
			Major: dev.Major,
			Minor: dev.Minor,
		})
	}
	return out
}

// RDMAEnabled returns true if the sandbox should set up RDMA support.
func RDMAEnabled(spec *specs.Spec, conf *config.Config) bool {
	return conf.RDMAProxy && specHasUverbsDevice(spec)
}

// specHasUverbsDevice reports whether the spec lists any
// /dev/infiniband/uverbs* device.
func specHasUverbsDevice(spec *specs.Spec) bool {
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
