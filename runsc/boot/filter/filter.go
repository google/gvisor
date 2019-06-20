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

// Package filter defines all syscalls the sandbox is allowed to make
// to the host, and installs seccomp filters to prevent prohibited
// syscalls in case it's compromised.
package filter

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	"gvisor.dev/gvisor/pkg/sentry/platform/kvm"
	"gvisor.dev/gvisor/pkg/sentry/platform/ptrace"
)

// Options are seccomp filter related options.
type Options struct {
	Platform      platform.Platform
	HostNetwork   bool
	ProfileEnable bool
	ControllerFD  int
}

// Install installs seccomp filters for based on the given platform.
func Install(opt Options) error {
	s := allowedSyscalls
	s.Merge(controlServerFilters(opt.ControllerFD))

	// Set of additional filters used by -race and -msan. Returns empty
	// when not enabled.
	s.Merge(instrumentationFilters())

	if opt.HostNetwork {
		Report("host networking enabled: syscall filters less restrictive!")
		s.Merge(hostInetFilters())
	}
	if opt.ProfileEnable {
		Report("profile enabled: syscall filters less restrictive!")
		s.Merge(profileFilters())
	}

	switch p := opt.Platform.(type) {
	case *ptrace.PTrace:
		s.Merge(ptraceFilters())
	case *kvm.KVM:
		s.Merge(kvmFilters())
	default:
		return fmt.Errorf("unknown platform type %T", p)
	}

	return seccomp.Install(s)
}

// Report writes a warning message to the log.
func Report(msg string) {
	log.Warningf("*** SECCOMP WARNING: %s", msg)
}
