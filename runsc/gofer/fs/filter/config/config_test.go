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
	"runtime"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/bpf"
	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/pkg/seccomp/precompiledseccomp"
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
	configFields := map[string]mutateFn{
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
		"VendorSyscalls": func(opt *Options) {
			if len(opt.VendorSyscalls) == 0 {
				opt.VendorSyscalls = precompiledseccomp.VarSyscallNumbers{"test": 1000}
			} else {
				opt.VendorSyscalls = nil
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

// TestPrecompiledProgramsDeterministic verifies that compiling programs
// concurrently produces the same output as compiling them one at a time.
func TestPrecompiledProgramsDeterministic(t *testing.T) {
	// Make sure that compilations run in parallel even with few CPUs.
	const minProcs = 8
	if runtime.GOMAXPROCS(0) < minProcs {
		defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(minProcs))
	}
	serial, err := precompiledPrograms(1)
	if err != nil {
		t.Fatalf("precompiledPrograms(1) failed: %v", err)
	}
	concurrent, err := PrecompiledPrograms()
	if err != nil {
		t.Fatalf("PrecompiledPrograms() failed: %v", err)
	}
	if len(serial) != len(concurrent) {
		t.Fatalf("got %d programs when compiling concurrently, want %d", len(concurrent), len(serial))
	}
	for i := range serial {
		if !reflect.DeepEqual(serial[i], concurrent[i]) {
			t.Errorf("program %d (%q) differs between serial and concurrent compilation (concurrent name: %q)", i, serial[i].Name, concurrent[i].Name)
		}
	}
}

func TestMknodat(t *testing.T) {
	atFDCWD32 := int32(linux.AT_FDCWD)
	atFDCWD64 := int64(linux.AT_FDCWD)
	for _, directFS := range []bool{false, true} {
		rules, denyRules := Rules(Options{DirectFS: directFS})
		program := seccomp.Program{
			RuleSets: []seccomp.RuleSet{
				{Rules: denyRules},
				{Rules: rules, Action: seccomp.Allow},
			},
			Options: seccomp.ProgramOptions{DefaultAction: seccomp.KillProcess},
		}
		insns, _, err := program.Build()
		if err != nil {
			t.Fatal(err)
		}
		compiled, err := bpf.Compile(insns, true /* optimize */)
		if err != nil {
			t.Fatal(err)
		}
		lisafsEnabled := !directFS
		for _, tc := range []struct {
			name    string
			args    [6]uint64
			allowed bool
		}{
			{"regular file", [6]uint64{10, 0x1000, unix.S_IFREG | 0o644, 0}, lisafsEnabled},
			{"regular file setuid sticky", [6]uint64{0, 0x1000, unix.S_IFREG | 0o7777, 0}, lisafsEnabled},
			{"whiteout char device", [6]uint64{10, 0x1000, unix.S_IFCHR, 0}, lisafsEnabled},
			{"whiteout char device with perms", [6]uint64{10, 0x1000, unix.S_IFCHR | 0o644, 0}, lisafsEnabled},
			{"non-whiteout char device", [6]uint64{10, 0x1000, unix.S_IFCHR | 0o666, 0x0103}, false},
			{"regular file nonzero dev", [6]uint64{10, 0x1000, unix.S_IFREG | 0o644, 1}, false},
			{"dev high bits set", [6]uint64{10, 0x1000, unix.S_IFCHR, 1 << 32}, false},
			{"zero file type", [6]uint64{10, 0x1000, 0o644, 0}, false},
			{"fifo", [6]uint64{10, 0x1000, unix.S_IFIFO | 0o644, 0}, false},
			{"socket", [6]uint64{10, 0x1000, unix.S_IFSOCK | 0o644, 0}, false},
			{"block device", [6]uint64{10, 0x1000, unix.S_IFBLK | 0o644, 0}, false},
			{"directory", [6]uint64{10, 0x1000, unix.S_IFDIR | 0o755, 0}, false},
			{"symlink", [6]uint64{10, 0x1000, unix.S_IFLNK | 0o777, 0}, false},
			{"AT_FDCWD 32-bit", [6]uint64{uint64(uint32(atFDCWD32)), 0x1000, unix.S_IFREG | 0o644, 0}, false},
			{"AT_FDCWD 64-bit", [6]uint64{uint64(atFDCWD64), 0x1000, unix.S_IFREG | 0o644, 0}, false},
			{"negative FD", [6]uint64{^uint64(0), 0x1000, unix.S_IFREG | 0o644, 0}, false},
		} {
			data := linux.SeccompData{Nr: unix.SYS_MKNODAT, Arch: seccomp.LINUX_AUDIT_ARCH, Args: tc.args}
			got, err := bpf.Exec[bpf.NativeEndian](compiled, seccomp.DataAsBPFInput(&data, make([]byte, data.SizeBytes())))
			if err != nil {
				t.Fatalf("directFS=%t %s: %v", directFS, tc.name, err)
			}
			if allowed := got == uint32(linux.SECCOMP_RET_ALLOW); allowed != tc.allowed {
				t.Errorf("directFS=%t %s: action=%#x, want allowed=%t", directFS, tc.name, got, tc.allowed)
			}
		}
	}
}
