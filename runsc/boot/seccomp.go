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
	"fmt"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"gvisor.dev/gvisor/pkg/bpf"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/specutils/seccomp"
)

func buildOCISeccompProgram(conf *config.Config, spec *specs.Spec) (*bpf.Program, error) {
	if !conf.OCISeccomp {
		if spec.Linux != nil && spec.Linux.Seccomp != nil {
			log.Warningf("Seccomp spec is being ignored because oci-seccomp is disabled")
		}
		return nil, nil
	}

	if spec.Linux == nil || spec.Linux.Seccomp == nil {
		return nil, nil
	}

	program, err := seccomp.BuildProgram(spec.Linux.Seccomp)
	if err != nil {
		return nil, fmt.Errorf("building seccomp program: %w", err)
	}

	if log.IsLogging(log.Debug) {
		out, _ := bpf.DecodeProgram(program)
		log.Debugf("Installing OCI seccomp filters\nProgram:\n%s", out)
	}

	return &program, nil
}
