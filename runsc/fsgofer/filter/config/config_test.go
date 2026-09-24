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
	"reflect"
	"testing"

	"gvisor.dev/gvisor/pkg/seccomp"
)

// TestOptionsConfigKey verifies the behavior of `Options.ConfigKey`.
func TestOptionsConfigKey(t *testing.T) {
	// mutateFn mutates the value of a specific Options field.
	type mutateFn func(opt *Options)

	var defaultOpt Options

	// Map of `Options` struct field names mapped to a function to mutate them.
	// This should only contain fields which influence the configuration.
	// Calling the mutation function of these should change the value of
	// `Options.ConfigKey`.
	var configFields = map[string]mutateFn{
		"UDSOpenEnabled":   func(opt *Options) { opt.UDSOpenEnabled = !opt.UDSOpenEnabled },
		"UDSCreateEnabled": func(opt *Options) { opt.UDSCreateEnabled = !opt.UDSCreateEnabled },
		"ProfileEnabled":   func(opt *Options) { opt.ProfileEnabled = !opt.ProfileEnabled },
		"DirectFS":         func(opt *Options) { opt.DirectFS = !opt.DirectFS },
		"LisafsNeeded":     func(opt *Options) { opt.LisafsNeeded = !opt.LisafsNeeded },
		"CgoEnabled":       func(opt *Options) { opt.CgoEnabled = !opt.CgoEnabled },
		"ExtraRules": func(opt *Options) {
			if len(opt.ExtraRules) == 0 {
				opt.ExtraRules = []seccomp.SyscallRules{
					seccomp.NewSyscallRules().Add(uintptr(123456), seccomp.MatchAll{}),
				}
			} else {
				opt.ExtraRules = nil
			}
		},
	}

	t.Run("fields are exhaustive", func(t *testing.T) {
		for i := 0; i < reflect.ValueOf(defaultOpt).NumField(); i++ {
			f := reflect.TypeOf(defaultOpt).Field(i)
			if _, found := configFields[f.Name]; !found {
				t.Fatalf("field `Options.%s` is not known to TestOptionsConfigKey; please add it", f.Name)
			}
		}
	})

	t.Run("mutating config fields causes ConfigKey to change", func(t *testing.T) {
		opt := defaultOpt // Make a copy, as we're about to mutate it.
		key := opt.ConfigKey()
		for name, mutateFn := range configFields {
			mutateFn(&opt)
			newKey := opt.ConfigKey()
			if key == newKey {
				t.Fatalf("mutating config field %q did not cause the ConfigKey to change: %q", name, key)
			}
			key = newKey
		}
	})
}

// TestPrecompiledPrograms verifies that all option variants precompile
// successfully, that their names are unique, and that each of them renders
// with the variable values that this process would use at runtime.
func TestPrecompiledPrograms(t *testing.T) {
	programs, err := PrecompiledPrograms()
	if err != nil {
		t.Fatalf("PrecompiledPrograms() failed: %v", err)
	}
	byName := make(map[string]int, len(programs))
	for i, program := range programs {
		if prev, dup := byName[program.Name]; dup {
			t.Errorf("programs %d and %d have the same name: %q", prev, i, program.Name)
		}
		byName[program.Name] = i
	}
	for _, opt := range optionsToPrecompile() {
		i, found := byName[opt.ConfigKey()]
		if !found {
			t.Errorf("no precompiled program for options %v", opt.ConfigKey())
			continue
		}
		if _, err := programs[i].RenderInstructions(opt.Vars()); err != nil {
			t.Errorf("cannot render precompiled program for options %v: %v", opt.ConfigKey(), err)
		}
	}
}
