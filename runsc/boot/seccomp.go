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

package boot

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/specutils/seccomp"
)

// ociSeccompCache maps the hash of an OCI seccomp profile to its built
// filter. Containers in a pod usually share one profile, so the sandbox
// builds it one time.
// kernel.SyscallFilter is immutable, so tasks can share it.
var ociSeccompCache = struct {
	mu      sync.Mutex
	filters map[[sha256.Size]byte]*kernel.SyscallFilter
}{filters: make(map[[sha256.Size]byte]*kernel.SyscallFilter)}

func buildOCISeccompFilter(conf *config.Config, spec *specs.Spec) (*kernel.SyscallFilter, error) {
	if !conf.OCISeccomp {
		if spec.Linux != nil && spec.Linux.Seccomp != nil {
			log.Warningf("Seccomp spec is being ignored because oci-seccomp is disabled")
		}
		return nil, nil
	}

	if spec.Linux == nil || spec.Linux.Seccomp == nil {
		return nil, nil
	}

	profile, err := json.Marshal(spec.Linux.Seccomp)
	if err != nil {
		return nil, fmt.Errorf("encoding seccomp profile: %w", err)
	}
	key := sha256.Sum256(profile)

	ociSeccompCache.mu.Lock()
	filter, ok := ociSeccompCache.filters[key]
	ociSeccompCache.mu.Unlock()
	if !ok {
		f, err := seccomp.BuildFilter(spec.Linux.Seccomp)
		if err != nil {
			return nil, fmt.Errorf("building seccomp filter: %w", err)
		}
		filter = &f
		ociSeccompCache.mu.Lock()
		ociSeccompCache.filters[key] = filter
		ociSeccompCache.mu.Unlock()
	}

	if log.IsLogging(log.Debug) {
		log.Debugf("Installing OCI seccomp filter\n%v", filter)
	}

	return filter, nil
}
