package boot

import (
	"fmt"

	"github.com/opencontainers/runtime-spec/specs-go"

	"gvisor.dev/gvisor/pkg/bpf"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/specutils/seccomp"
)

// buildOCISeccompProgram builds a seccomp BPF program from the OCI spec.
// Returns nil if OCI seccomp is disabled or the spec has no seccomp config.
func buildOCISeccompProgram(conf *config.Config, spec *specs.Spec) (*bpf.Program, error) {
	if !conf.OCISeccomp {
		if spec.Linux != nil && spec.Linux.Seccomp != nil {
			log.Warningf("Seccomp spec is being ignored")
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
