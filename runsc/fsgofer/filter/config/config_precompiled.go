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

package config

import (
	"fmt"

	"golang.org/x/sync/errgroup"

	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/pkg/seccomp/precompiledseccomp"
	"gvisor.dev/gvisor/pkg/sync"
)

// optionsToPrecompile returns the set of `Options` for which we should
// precompile seccomp filters.
func optionsToPrecompile() []Options {
	opts := []Options{{}}
	for _, fn := range []func(opt Options) []Options{
		// Expand host UDS support (open and create are independent).
		func(opt Options) []Options {
			udsOpenYes := opt
			udsOpenYes.UDSOpenEnabled = true
			udsOpenNo := opt
			udsOpenNo.UDSOpenEnabled = false
			return []Options{udsOpenYes, udsOpenNo}
		},
		func(opt Options) []Options {
			udsCreateYes := opt
			udsCreateYes.UDSCreateEnabled = true
			udsCreateNo := opt
			udsCreateNo.UDSCreateEnabled = false
			return []Options{udsCreateYes, udsCreateNo}
		},

		// cgo enabled and disabled.
		func(opt Options) []Options {
			cgoYes := opt
			cgoYes.CgoEnabled = true
			cgoNo := opt
			cgoNo.CgoEnabled = false
			return []Options{cgoYes, cgoNo}
		},

		// Only consider profiling disabled.
		func(opt Options) []Options {
			noProfile := opt
			noProfile.ProfileEnabled = false
			return []Options{noProfile}
		},

		// DirectFS: both on and off.
		func(opt Options) []Options {
			directfs := opt
			directfs.DirectFS = true
			noDirectfs := opt
			noDirectfs.DirectFS = false
			return []Options{directfs, noDirectfs}
		},
		// LisaFS: Both on and off.
		// Which one is used depends on the set of mounts of the sandbox.
		func(opt Options) []Options {
			lisafs := opt
			lisafs.LisafsNeeded = true
			noLisafs := opt
			noLisafs.LisafsNeeded = false
			return []Options{lisafs, noLisafs}
		},
	} {
		var newOpts []Options
		for _, opt := range opts {
			newOpts = append(newOpts, fn(opt)...)
		}
		opts = newOpts
	}
	return opts
}

// PrecompiledPrograms returns the set of seccomp programs to precompile.
func PrecompiledPrograms() ([]precompiledseccomp.Program, error) {
	opts := optionsToPrecompile()
	programs := make([]precompiledseccomp.Program, len(opts))
	var programsMu sync.Mutex
	var errGroup errgroup.Group
	for i, opt := range opts {
		i, opt := i, opt
		errGroup.Go(func() error {
			var varNames []string
			for varName := range opt.Vars() {
				varNames = append(varNames, varName)
			}
			program, err := precompiledseccomp.Precompile(opt.ConfigKey(), varNames, func(vars precompiledseccomp.Values) *seccomp.Program {
				rules, denyRules := rules(opt, vars)
				return &seccomp.Program{
					RuleSets: []seccomp.RuleSet{
						{
							Rules: denyRules.Copy(),
						},
						{
							Rules:  rules.Copy(),
							Action: seccomp.Allow,
						},
					},
				}
			})
			if err != nil {
				return fmt.Errorf("cannot precompile seccomp program for options %v: %w", opt.ConfigKey(), err)
			}
			programsMu.Lock()
			defer programsMu.Unlock()
			programs[i] = program
			return nil
		})
	}
	if err := errGroup.Wait(); err != nil {
		return nil, err
	}
	return programs, nil
}
