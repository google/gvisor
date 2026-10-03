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

package filter

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/pkg/seccomp/precompiledseccomp"
)

// ***   DEBUG TIP   ***
// If you suspect a gofer is getting killed due to a seccomp violation,
// change this to `true` to get a panic stack trace when there is a
// violation.
const debugFilter = false

// SelfPIDVarName is the variable name for the current process ID used in
// precompiled seccomp filters.
const SelfPIDVarName = "self_pid"

// SelfPIDFilters returns syscall filters that depend on the process's PID.
func SelfPIDFilters(pid uint64) seccomp.SyscallRules {
	return seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
		unix.SYS_TGKILL: seccomp.PerArg{
			seccomp.EqualTo(pid),
		},
	})
}

// ConfigOptions represents seccomp filter configuration options for a gofer.
type ConfigOptions interface {
	ConfigKey() string
	Warnings() []string
	Vars() precompiledseccomp.Values
	Rules() (seccomp.SyscallRules, seccomp.SyscallRules)
}

// Install installs seccomp filters for a gofer process using precompiled
// programs when available.
func Install[Opts ConfigOptions](
	opt Opts,
	getPrecompiled func(string) (precompiledseccomp.Program, bool),
	listPrecompiled func() []string,
) error {
	for _, warning := range opt.Warnings() {
		log.Warningf("*** SECCOMP WARNING: %s", warning)
	}
	key := opt.ConfigKey()
	precompiled, usePrecompiled := getPrecompiled(key)
	if usePrecompiled && !debugFilter {
		vars := opt.Vars()
		log.Debugf("Loaded precompiled seccomp instructions for options %v, using variables: %v", key, vars)
		insns, err := precompiled.RenderInstructions(vars)
		if err == nil {
			return seccomp.SetFilter(insns)
		}
		if !errors.Is(err, precompiledseccomp.ErrSyscallVarsNotRenderable) {
			return fmt.Errorf("cannot render precompiled program for options %v / vars %v: %w", key, vars, err)
		}
		log.Warningf("Cannot use precompiled program for config options %v (%v), building seccomp program from scratch. This slows down gofer startup.", key, err)
	}
	var seccompOpts seccomp.ProgramOptions
	if debugFilter {
		log.Infof("Seccomp filter debugging is enabled; seccomp failures will result in a panic stack trace.")
		seccompOpts.DefaultAction = seccomp.Trap
	} else if !usePrecompiled {
		log.Warningf("No precompiled program found for config options %v, building seccomp program from scratch. This slows down gofer startup.", key)
		if log.IsLogging(log.Debug) {
			precompiledKeys := listPrecompiled()
			log.Debugf("Precompiled seccomp-bpf program configuration option variants (%d):", len(precompiledKeys))
			for _, k := range precompiledKeys {
				log.Debugf("  %v", k)
			}
		}
	}
	rules, denyRules := opt.Rules()
	program := &seccomp.Program{
		RuleSets: []seccomp.RuleSet{
			{
				Rules: denyRules,
			},
			{
				Rules:  rules,
				Action: seccomp.Allow,
			},
		},
		Options: seccompOpts,
	}
	return program.Install(nil /* timer */)
}
