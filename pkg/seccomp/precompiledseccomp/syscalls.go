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

package precompiledseccomp

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"gvisor.dev/gvisor/pkg/seccomp"
)

// Syscall number variables
//
// Some syscalls (e.g. vendor-specific syscalls) have syscall numbers that
// are only known at runtime. They can still be part of precompiled programs
// by representing their syscall number as a variable.
//
// The set of syscall numbers in a program determines the structure of its
// bytecode, as syscall numbers are looked up using a binary search tree.
// Therefore, a program precompiled with syscall number variables is only
// valid if the syscall numbers it is rendered with are ordered the same way
// (relative to each other and to the other syscall numbers in the program)
// as the values that the variables had during precompilation.

// MinSyscallVarValue is the minimum value that syscall number variables
// may have when rendering a precompiled program. Precompiled programs that
// contain syscall number variables may not contain any other syscall number
// within [`MinSyscallVarValue`, `MaxSyscallVarValue`).
const MinSyscallVarValue = 500

// MaxSyscallVarValue is the (exclusive) maximum value that syscall number
// variables may have when rendering a precompiled program.
const MaxSyscallVarValue = 0x80000000

// syscallVarPrefix is the prefix for the names of syscall number variables.
const syscallVarPrefix = "sysno_"

// ErrSyscallVarsNotRenderable is returned when the values of syscall number
// variables are out of bounds.
var ErrSyscallVarsNotRenderable = errors.New("syscall number variables cannot be rendered into precompiled program")

// SyscallVarName returns the name of the syscall number variable for the
// syscall with the given name.
func SyscallVarName(name string) string {
	return syscallVarPrefix + name
}

// isSyscallVarName returns whether `varName` is the name of a syscall
// number variable.
func isSyscallVarName(varName string) bool {
	return strings.HasPrefix(varName, syscallVarPrefix)
}

// SetSyscall sets the value of the syscall number variable for the syscall
// with the given name.
func (v Values) SetSyscall(name string, sysno uintptr) {
	v[SyscallVarName(name)] = uint32(sysno)
}

// GetSyscall retrieves the value of the syscall number variable for the
// syscall with the given name, as set using `Values.SetSyscall(name)`.
func (v Values) GetSyscall(name string) uintptr {
	return uintptr(v[SyscallVarName(name)])
}

// PopSyscall retrieves the value of the syscall number variable for the
// syscall with the given name and removes it from `v`.
func (v Values) PopSyscall(name string) uintptr {
	sysno := v.GetSyscall(name)
	delete(v, SyscallVarName(name))
	return sysno
}

// checkSyscallVarsRenderable verifies that the syscall number variables in
// `v` can be rendered into a program precompiled with them.
func (v Values) checkSyscallVarsRenderable() error {
	var varNames []string
	for varName := range v {
		if isSyscallVarName(varName) {
			varNames = append(varNames, varName)
		}
	}
	sort.Strings(varNames)
	for i, varName := range varNames {
		if v[varName] < MinSyscallVarValue || v[varName] >= MaxSyscallVarValue {
			return fmt.Errorf("%w: variable %q has value %d, which is not within [%d, %d)", ErrSyscallVarsNotRenderable, varName, v[varName], MinSyscallVarValue, MaxSyscallVarValue)
		}
		if i > 0 && v[varName] <= v[varNames[i-1]] {
			return fmt.Errorf("%w: variable %q has value %d, which is not greater than the value %d of variable %q", ErrSyscallVarsNotRenderable, varName, v[varName], v[varNames[i-1]], varNames[i-1])
		}
	}
	return nil
}

// checkSyscallVarsPrecompilable verifies that `prog`, built with `values`,
// can be precompiled into a renderable program.
func checkSyscallVarsPrecompilable(prog *seccomp.Program, values Values) error {
	varSysnos := make(map[uintptr]string)
	for varName, value := range values {
		if isSyscallVarName(varName) {
			if value < MinSyscallVarValue || value >= MaxSyscallVarValue {
				return fmt.Errorf("syscall number variable %q has placeholder value %d, which is not within [%d, %d)", varName, value, MinSyscallVarValue, MaxSyscallVarValue)
			}
			varSysnos[uintptr(value)] = varName
		}
	}
	if len(varSysnos) == 0 {
		return nil
	}
	for _, ruleSet := range prog.RuleSets {
		for _, sysno := range ruleSet.Rules.Sysnos() {
			if _, isVar := varSysnos[sysno]; isVar {
				continue
			}
			if sysno >= MinSyscallVarValue && sysno < MaxSyscallVarValue {
				return fmt.Errorf("program has a rule for syscall number %d, which is within [%d, %d); this is not supported in programs with syscall number variables", sysno, MinSyscallVarValue, MaxSyscallVarValue)
			}
		}
	}
	return nil
}

// VarSyscall is a syscall whose syscall number is only known at runtime.
type VarSyscall struct {
	// Name is the syscall name.
	// Within a set of `VarSyscall`s, names must be in the same order as
	// their syscall numbers.
	Name string

	// HostSysno returns the syscall number of the syscall on the current
	// host, and whether the syscall may be used on the current host.
	HostSysno func() (uintptr, bool)

	// Rule is the rule for the syscall.
	Rule seccomp.SyscallRule
}

// VarSyscallNumbers maps the names of `VarSyscall`s to their syscall number.
type VarSyscallNumbers map[string]uintptr

// HostSupportedVariableSyscallNumbers returns the syscall numbers of the `VarSyscall`s in
// `syscalls` which may be used on the current host.
func HostSupportedVariableSyscallNumbers(syscalls []VarSyscall) VarSyscallNumbers {
	sn := make(VarSyscallNumbers, len(syscalls))
	for _, s := range syscalls {
		if sysno, ok := s.HostSysno(); ok {
			sn[s.Name] = sysno
		}
	}
	return sn
}

// AllVarSyscallNumbers returns a `VarSyscallNumbers` with all the syscalls in
// `syscalls`, with arbitrary syscall numbers that are valid for rendering
// programs precompiled with them.
func AllVarSyscallNumbers(syscalls []VarSyscall) VarSyscallNumbers {
	names := make([]string, 0, len(syscalls))
	for _, s := range syscalls {
		names = append(names, s.Name)
	}
	return PrecompileSyscallNumbers(names...)
}

// PrecompileSyscallNumbers returns a `VarSyscallNumbers` with the syscalls
// with the given names, with arbitrary syscall numbers that are valid for
// rendering programs precompiled with them.
func PrecompileSyscallNumbers(names ...string) VarSyscallNumbers {
	names = append([]string(nil), names...)
	sort.Strings(names)
	sn := make(VarSyscallNumbers, len(names))
	for i, name := range names {
		sn[name] = uintptr(MinSyscallVarValue + i)
	}
	return sn
}

// Key returns a string representing the set of syscalls in `sn`, but not
// their syscall numbers. It is meant to be used as part of a configuration
// key.
func (sn VarSyscallNumbers) Key() string {
	names := make([]string, 0, len(sn))
	for name := range sn {
		names = append(names, name)
	}
	sort.Strings(names) // Key needs to be consistent.
	return strings.Join(names, ",")
}

// SetVars sets the syscall number variables of the syscalls in `sn`.
func (sn VarSyscallNumbers) SetVars(vars Values) {
	for name, sysno := range sn {
		vars.SetSyscall(name, sysno)
	}
}

// VarSyscallRules returns the rules for the syscalls in `syscalls` which
// are present in `sn`, using the syscall number variables from `vars`.
func VarSyscallRules(syscalls []VarSyscall, sn VarSyscallNumbers, vars Values) seccomp.SyscallRules {
	rules := seccomp.NewSyscallRules()
	for _, s := range syscalls {
		if _, ok := sn[s.Name]; ok {
			rules.Add(vars.GetSyscall(s.Name), s.Rule)
		}
	}
	return rules
}
