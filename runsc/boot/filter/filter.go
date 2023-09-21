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
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/pkg/sentry/devices/accel"
	"gvisor.dev/gvisor/pkg/sentry/devices/nvproxy"
	"gvisor.dev/gvisor/pkg/sentry/platform"
)

// Options are seccomp filter related options.
type Options struct {
	Platform              platform.Platform
	HostNetwork           bool
	HostNetworkRawSockets bool
	HostFilesystem        bool
	ProfileEnable         bool
	NVProxy               bool
	TPUProxy              bool
	ControllerFD          int
}

// Rules returns the seccomp (rules, denyRules) to use for the Sentry.
func Rules(opt Options) (seccomp.SyscallRules, seccomp.SyscallRules) {
	s := allowedSyscalls
	s.Merge(controlServerFilters(opt.ControllerFD))

	// Set of additional filters used by -race and -msan. Returns empty
	// when not enabled.
	s.Merge(instrumentationFilters())

	if opt.HostNetwork {
		if opt.HostNetworkRawSockets {
			Report("host networking (with raw sockets) enabled: syscall filters less restrictive!")
		} else {
			Report("host networking enabled: syscall filters less restrictive!")
		}
		s.Merge(hostInetFilters(opt.HostNetworkRawSockets))
	}
	if opt.ProfileEnable {
		Report("profile enabled: syscall filters less restrictive!")
		s.Merge(profileFilters())
	}
	if opt.HostFilesystem {
		Report("host filesystem enabled: syscall filters less restrictive!")
		s.Merge(hostFilesystemFilters())
	}
	if opt.NVProxy {
		Report("Nvidia GPU driver proxy enabled: syscall filters less restrictive!")
		s.Merge(nvproxy.Filters())
	}
	if opt.TPUProxy {
		Report("TPU device proxy enabled: syscall filters less restrictive!")
		s.Merge(accel.Filters())
	}

	s.Merge(opt.Platform.SyscallFilters())

	return s, seccomp.DenyNewExecMappings
}

// Install seccomp filters based on the given platform.
func Install(opt Options) error {
	rules, denyRules := Rules(opt)
	return seccomp.Install(rules, denyRules)
}

// Report writes a warning message to the log.
func Report(msg string) {
	log.Warningf("*** SECCOMP WARNING: %s", msg)
}
