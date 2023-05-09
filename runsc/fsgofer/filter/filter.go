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

// Package filter defines all syscalls the gofer is allowed to make, and
// installs seccomp filters to prevent prohibited syscalls in case it's
// compromised.
package filter

import (
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/seccomp"
)

// Options are seccomp filter related options.
type Options struct {
	UDSOpenEnabled   bool
	UDSCreateEnabled bool
	ProfileEnabled   bool
}

// Install installs seccomp filters.
func Install(opt Options) error {
	s := allowedSyscalls

	if opt.ProfileEnabled {
		report("profile enabled: syscall filters less restrictive!")
		s.Merge(profileFilters)
	}

	if opt.UDSOpenEnabled || opt.UDSCreateEnabled {
		report("host UDS enabled: syscall filters less restrictive!")
		s.Merge(udsCommonSyscalls)
		if opt.UDSOpenEnabled {
			s.Merge(udsOpenSyscalls)
		}
		if opt.UDSCreateEnabled {
			s.Merge(udsCreateSyscalls)
		}
	}

	// Set of additional filters used by -race and -msan. Returns empty
	// when not enabled.
	s.Merge(instrumentationFilters())

	return seccomp.Install(s, seccomp.DenyNewExecMappings)
}

// report writes a warning message to the log.
func report(msg string) {
	log.Warningf("*** SECCOMP WARNING: %s", msg)
}
