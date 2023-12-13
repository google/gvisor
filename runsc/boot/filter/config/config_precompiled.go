// Copyright 2023 The gVisor Authors.
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
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/pkg/seccomp/precompiledseccomp"
	"gvisor.dev/gvisor/pkg/sentry/platform"

	// Import platforms that we need to precompile filters for.
	_ "gvisor.dev/gvisor/runsc/boot/platforms"
)

// Variable names used in precompiled filters.
const (
	// controllerFDVarName is the variable name for `Options.ControllerFD`
	// used in the precompiled seccomp filters.
	controllerFDVarName = "controller_fd"

	// selfPIDVarName is the variable name for the current process ID.
	selfPIDVarName = "self_pid"
)

// allPrecompiledPlatforms returns a list of `platform.SeccompInfo` instances
// that should be precompiled into seccomp programs.
func allPrecompiledPlatforms() ([]platform.SeccompInfo, error) {
	var seccompInfos []platform.SeccompInfo
	for _, platformName := range platform.List() {
		constructor, err := platform.Lookup(platformName)
		if err != nil {
			return nil, fmt.Errorf("cannot lookup platform %q: %w", platformName, err)
		}
		for _, si := range constructor.PrecompiledSeccompInfo() {
			seccompInfos = append(seccompInfos, si)
		}
	}
	return seccompInfos, nil
}

// optionsToPrecompile returns the set of `Options` for which we should
// precompile seccomp filters.
func optionsToPrecompile() ([]Options, error) {
	type expandFn func(opt Options) ([]Options, error)
	opts := []Options{Options{}}
	for _, fn := range []expandFn{
		// Expand all platforms.
		func(opt Options) ([]Options, error) {
			var newOpts []Options
			platforms, err := allPrecompiledPlatforms()
			if err != nil {
				return nil, err
			}
			for _, platform := range platforms {
				optCopy := opt
				optCopy.Platform = platform
				newOpts = append(newOpts, optCopy)
			}
			return newOpts, nil
		},

		// Only precompile options with host networking disabled.
		func(opt Options) ([]Options, error) {
			opt.HostNetwork = false
			return []Options{opt}, nil
		},

		// Only precompile options with DirectFS enabled.
		func(opt Options) ([]Options, error) {
			opt.HostFilesystem = true
			return []Options{opt}, nil
		},

		// Expand NVProxy vs not.
		func(opt Options) ([]Options, error) {
			nvProxyYes := opt
			nvProxyYes.NVProxy = true
			nvProxyNo := opt
			nvProxyNo.NVProxy = false
			return []Options{nvProxyYes, nvProxyNo}, nil
		},

		// Expand TPUProxy vs not.
		func(opt Options) ([]Options, error) {
			tpuProxyYes := opt
			tpuProxyYes.TPUProxy = true
			tpuProxyNo := opt
			tpuProxyNo.TPUProxy = false
			return []Options{tpuProxyYes, tpuProxyNo}, nil
		},
	} {
		var newOpts []Options
		for _, opt := range opts {
			expanded, err := fn(opt)
			if err != nil {
				return nil, err
			}
			for _, newOpt := range expanded {
				newOpts = append(newOpts, newOpt)
			}
		}
		opts = newOpts
	}
	return opts, nil
}

// PrecompiledPrograms returns the set of seccomp programs to precompile.
func PrecompiledPrograms() ([]precompiledseccomp.Program, error) {
	opts, err := optionsToPrecompile()
	if err != nil {
		return nil, err
	}
	programs := make([]precompiledseccomp.Program, len(opts))
	var errGroup errgroup.Group
	for i, opt := range opts {
		i, opt := i, opt
		errGroup.Go(func() error {
			var varNames []string
			for varName := range opt.Vars() {
				varNames = append(varNames, varName)
			}
			program, err := precompiledseccomp.Precompile(opt.ConfigKey(), varNames, func(vars precompiledseccomp.Values) precompiledseccomp.ProgramDesc {
				opt := opt
				seccompOpts := SeccompOptions(opt)
				rules, denyRules := rules(opt, vars)
				return precompiledseccomp.ProgramDesc{
					Rules: []seccomp.RuleSet{
						{
							Rules:  denyRules.Copy(),
							Action: seccompOpts.DefaultAction,
						},
						{
							Rules:  rules.Copy(),
							Action: linux.SECCOMP_RET_ALLOW,
						},
					},
					SeccompOptions: seccompOpts,
				}
			})
			if err != nil {
				return fmt.Errorf("cannot precompile seccomp program for options %v: %w", opt.ConfigKey(), err)
			}
			programs[i] = program
			return nil
		})
	}
	if err := errGroup.Wait(); err != nil {
		return nil, err
	}
	return programs, nil
}
