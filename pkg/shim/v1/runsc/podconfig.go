// Copyright 2026 The gVisor Authors.
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

package runsc

import (
	"fmt"
	"strings"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/types/known/anypb"
)

// podSandboxConfigType is the type URL of a CRI runtime.v1.PodSandboxConfig.
const podSandboxConfigType = "runtime.v1.PodSandboxConfig"

// podSandboxConfig holds the fields of a CRI runtime.v1.PodSandboxConfig that
// the shim uses. It is decoded by hand rather than with k8s.io/cri-api; the
// field numbers are from its api.proto.
type podSandboxConfig struct {
	name         string
	uid          string
	namespace    string
	hostname     string
	logDirectory string
	annotations  map[string]string
	cgroupParent string
	sysctls      map[string]string
	hostNetwork  bool
	resources    *podResources
}

// podResources is the subset of a CRI LinuxContainerResources the shim uses.
type podResources struct {
	cpuPeriod   int64
	cpuQuota    int64
	cpuShares   int64
	memoryLimit int64
}

// namespaceModeNode is NamespaceMode NODE: the pod uses the host namespace.
const namespaceModeNode = 2

// unmarshalPodSandboxConfig decodes a PodSandboxConfig from a.
func unmarshalPodSandboxConfig(a *anypb.Any) (*podSandboxConfig, error) {
	url := a.GetTypeUrl()
	if url[strings.LastIndex(url, "/")+1:] != podSandboxConfigType {
		return nil, fmt.Errorf("options have type %q, want %q", url, podSandboxConfigType)
	}
	c := &podSandboxConfig{}
	err := forEachField(a.GetValue(), func(num protowire.Number, v []byte, n uint64) error {
		switch num {
		case 1: // metadata
			return forEachField(v, func(num protowire.Number, v []byte, _ uint64) error {
				switch num {
				case 1:
					c.name = string(v)
				case 2:
					c.uid = string(v)
				case 3:
					c.namespace = string(v)
				}
				return nil
			})
		case 2:
			c.hostname = string(v)
		case 3:
			c.logDirectory = string(v)
		case 7:
			return addMapEntry(&c.annotations, v)
		case 8: // linux
			return c.decodeLinux(v)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", podSandboxConfigType, err)
	}
	return c, nil
}

// decodeLinux decodes a LinuxPodSandboxConfig into c.
func (c *podSandboxConfig) decodeLinux(b []byte) error {
	return forEachField(b, func(num protowire.Number, v []byte, _ uint64) error {
		switch num {
		case 1:
			c.cgroupParent = string(v)
		case 2: // security_context
			return forEachField(v, func(num protowire.Number, v []byte, _ uint64) error {
				if num != 1 { // namespace_options
					return nil
				}
				return forEachField(v, func(num protowire.Number, _ []byte, n uint64) error {
					if num == 1 { // network
						c.hostNetwork = n == namespaceModeNode
					}
					return nil
				})
			})
		case 3:
			return addMapEntry(&c.sysctls, v)
		case 5: // resources
			r := &podResources{}
			c.resources = r
			return forEachField(v, func(num protowire.Number, _ []byte, n uint64) error {
				switch num {
				case 1:
					r.cpuPeriod = int64(n)
				case 2:
					r.cpuQuota = int64(n)
				case 3:
					r.cpuShares = int64(n)
				case 4:
					r.memoryLimit = int64(n)
				}
				return nil
			})
		}
		return nil
	})
}

// addMapEntry decodes a map<string, string> entry into *m.
func addMapEntry(m *map[string]string, b []byte) error {
	var k, v string
	if err := forEachField(b, func(num protowire.Number, b []byte, _ uint64) error {
		switch num {
		case 1:
			k = string(b)
		case 2:
			v = string(b)
		}
		return nil
	}); err != nil {
		return err
	}
	if *m == nil {
		*m = make(map[string]string)
	}
	(*m)[k] = v
	return nil
}

// forEachField calls fn for each field of the encoded message b, with the
// payload of length-delimited fields in v and the value of varints in n.
// Fields of other wire types are skipped.
func forEachField(b []byte, fn func(num protowire.Number, v []byte, n uint64) error) error {
	for len(b) > 0 {
		num, typ, l := protowire.ConsumeTag(b)
		if l < 0 {
			return protowire.ParseError(l)
		}
		b = b[l:]
		var (
			v []byte
			n uint64
		)
		switch typ {
		case protowire.BytesType:
			v, l = protowire.ConsumeBytes(b)
		case protowire.VarintType:
			n, l = protowire.ConsumeVarint(b)
		default:
			l = protowire.ConsumeFieldValue(num, typ, b)
		}
		if l < 0 {
			return protowire.ParseError(l)
		}
		b = b[l:]
		if typ != protowire.BytesType && typ != protowire.VarintType {
			continue
		}
		if err := fn(num, v, n); err != nil {
			return err
		}
	}
	return nil
}
