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

// Package filter installs seccomp filters to prevent prohibited syscalls
// in case it's compromised.
package filter

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/runsc/boot/filter/config"
)

// ***   DEBUG TIP   ***
// If you suspect the Sentry is getting killed due to a seccomp violation,
// change this to `true` to get a panic stack trace when there is a
// violation.
const debugFilter = false

// Options is a re-export of the config Options type under this package.
type Options = config.Options

// Install seccomp filters based on the given platform.
func Install(opt Options) error {
	for _, warning := range config.Warnings(opt) {
		log.Warningf("*** SECCOMP WARNING: %s", warning)
	}
	key := opt.ConfigKey()
	precompiled, usePrecompiled := GetPrecompiled(key)
	if usePrecompiled && !debugFilter {
		vars := opt.Vars()
		log.Debugf("Loaded precompiled seccomp instructions for options %v, using variables: %v", key, vars)
		insns, err := precompiled.RenderInstructions(vars)
		if err != nil {
			return fmt.Errorf("cannot render precompiled program for options %v / vars %v: %w", key, vars, err)
		}
		return seccomp.SetFilter(insns)
	}
	seccompOpts := config.SeccompOptions(opt)
	if debugFilter {
		log.Infof("Seccomp filter debugging is enabled; seccomp failures will result in a panic stack trace.")
		seccompOpts.DefaultAction = linux.SECCOMP_RET_TRAP
	} else {
		log.Infof("No precompiled program found for config options %v, building seccomp program from scratch. This may slow down container startup.", key)
		if log.IsLogging(log.Debug) {
			precompiledKeys := ListPrecompiled()
			log.Debugf("Precompiled seccomp-bpf program configuration option variants (%d):", len(precompiledKeys))
			for k := range precompiledKeys {
				log.Debugf("  %v", k)
			}
		}
	}
	rules, denyRules := config.Rules(opt)
	return seccomp.Install(rules, denyRules, seccompOpts)
}
