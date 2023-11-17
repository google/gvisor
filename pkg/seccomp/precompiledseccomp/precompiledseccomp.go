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

// Package precompiledseccomp provides tooling to precompile seccomp-bpf
// programs that can be embedded inside Go source code.
package precompiledseccomp

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"

	"gvisor.dev/gvisor/pkg/bpf"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/seccomp"
)

// ProgramDesc describes a program to be compiled.
type ProgramDesc struct {
	// Rules contains the seccomp-bpf rulesets to compile.
	Rules []seccomp.RuleSet

	// SeccompOptions is the seccomp-bpf program options used in compilation.
	SeccompOptions seccomp.ProgramOptions
}

// Program is a precompiled seccomp-bpf program.
// To get actual BPF instructions, call the `RenderInstructions` function.
type Program struct {
	// Name is the name of this program within a set of embedded programs.
	Name string

	// Bytecode32 is the raw BPF bytecode represented as a sequence of uint32s.
	Bytecode32 []uint32

	// VarOffsets maps variable names to the uint32-based offsets where these
	// variables show up in `Bytecode32`.
	VarOffsets map[string][]int
}

// Values is an assignment of variables to uint32 values.
// It is used when rendering seccomp-bpf program instructions.
type Values map[string]uint32

const (
	uint64VarSuffixHigh = "_high32bits"
	uint64VarSuffixLow  = "_low32bits"
)

// SetUint64 sets the value of a 64-bit variable in `v`.
// Under the hood, this is stored as two 32-bit variables.
// Use `Values.GetUint64` to retrieve the 64-bit variable.
func (v Values) SetUint64(varName string, value uint64) {
	v[varName+uint64VarSuffixHigh] = uint32(value >> 32)
	v[varName+uint64VarSuffixLow] = uint32(value)
}

// GetUint64 retrieves the value of a 64-bit variable set using
// `Values.SetUint64(varName)`.
func (v Values) GetUint64(varName string) uint64 {
	return uint64(v[varName+"_high32bits"])<<32 | uint64(v[varName+"_low32bits"])
}

// Precompile compiles a `ProgramDesc` with the given values.
// It supports the notion of "variables", which are named in `vars`.
// Variables are uint32s which are only known at runtime, and whose value
// shows up in the BPF bytecode.
//
// `fn` takes in a mapping of variable names to their assigned values,
// and should return a `ProgramDesc` describing the seccomp-bpf program
// to be compiled.
//
// Precompile verifies that all variables in `vars` show up consistently in
// the bytecode by compiling the program twice, ensures that the offsets at
// which some stand-in values is consistent across these two compilation
// attempts, and that nothing else about the BPF bytecode is different.
func Precompile(name string, varNames []string, fn func(Values) ProgramDesc) (Program, error) {
	vars := make(map[string]struct{}, len(varNames))
	for _, varName := range varNames {
		vars[varName] = struct{}{}
	}
	if len(vars) != len(varNames) {
		return Program{}, fmt.Errorf("non-unique variable names: %q", varNames)
	}

	// These constants are chosen to be recognizable and unique within
	// seccomp-bpf programs.
	// These could of course show up in seccomp-bpf programs for legitimate
	// reasons other than being part the variable being matched against (e.g. a
	// jump of this many instructions forward, or a static equality match that
	// happens to check against this exact value), but it is very unlikely that
	// integers this large actually occur.
	// If it does happen, we'll catch it here because one compilation attempt
	// will find its placeholder values show up less often than the other.
	// Assuming that the reason this occurred is legitimate, update these
	// constants to even-less-likely values in order to fix this issue.
	const (
		varStart1 uint32 = 0x13371337
		varStart2 uint32 = 0x42424243
	)

	// Render the program with one set of values.
	// Remember at which offsets we saw these values show up in the bytecode.
	values1 := Values(make(map[string]uint32, len(vars)))
	v := varStart1
	for varName := range vars {
		values1[varName] = v
		v += 2
	}
	program1, err := precompile(name, values1, fn)
	if err != nil {
		return Program{}, err
	}

	// Do the same, but with a different set of values.
	values2 := Values(make(map[string]uint32, len(vars)))
	v = varStart2
	for _, varName := range varNames {
		values2[varName] = v
		v += 2
	}
	program2, err := precompile(name, values2, fn)
	if err != nil {
		return Program{}, err
	}

	// Ensure that the offsets we got is consistent.
	for _, varName := range varNames {
		offsets1 := program1.VarOffsets[varName]
		offsets2 := program2.VarOffsets[varName]
		if len(offsets1) != len(offsets2) {
			return Program{}, fmt.Errorf("var %q has different number of offsets depending on its value: with value 0x%08x it showed up %d times, but with value %d it showed up %d times", varName, values1[varName], len(offsets1), values2[varName], len(offsets2))
		}
		for i := 0; i < len(offsets1); i++ {
			if offsets1[i] != offsets2[i] {
				return Program{}, fmt.Errorf("var %q has different offsets depending on its value: with value 0x%08x it showed up at offsets %v, but with value %d it showed up at offsets %v", varName, values1[varName], offsets1, values2[varName], offsets2)
			}
		}
	}

	// Ensure that the rest of the bytecode is exactly equal.
	if len(program1.Bytecode32) != len(program2.Bytecode32) {
		return Program{}, fmt.Errorf("compiled programs do not have the same bytecode size: %d vs %d", len(program1.Bytecode32), len(program2.Bytecode32))
	}
	knownOffsets := map[int]struct{}{}
	for _, varName := range varNames {
		for _, offset := range program1.VarOffsets[varName] {
			knownOffsets[offset] = struct{}{}
		}
	}
	for i := 0; i < len(program1.Bytecode32); i++ {
		if _, isVarOffset := knownOffsets[i]; isVarOffset {
			continue
		}
		if program1.Bytecode32[i] != program2.Bytecode32[i] {
			return Program{}, fmt.Errorf("compiled programs do not have the same bytecode at uint32 offset %d (which is not any of the offsets where a variable shows up: %v)", i, knownOffsets)
		}
	}

	return program1, nil
}

// precompile compiles a `ProgramDesc` with the given values.
func precompile(name string, values Values, fn func(Values) ProgramDesc) (Program, error) {
	precompileOpts := fn(values)
	insns, _, err := seccomp.BuildProgram(precompileOpts.Rules, precompileOpts.SeccompOptions)
	if err != nil {
		return Program{}, err
	}
	if log.IsLogging(log.Debug) {
		log.Debugf("Compiled program with values %v (%d instructions):", values, len(insns))
		for i, insn := range insns {
			log.Debugf("  %04d: %s\n", i, insn.String())
		}
	}
	bytecode32 := instructionsToUint32Slice(insns)
	varOffsets := getVarOffsets(bytecode32, values)

	// nonOptimizedOffsets stores the offsets at which each variable shows up
	// in the non-optimized version of the program. It is only computed when
	// a variable doesn't show up in the optimized version of the program.
	var nonOptimizedOffsets map[string][]int
	computeNonOptimizedOffsets := func() error {
		if nonOptimizedOffsets != nil {
			return nil
		}
		if !precompileOpts.SeccompOptions.Optimize {
			nonOptimizedOffsets = varOffsets
			return nil
		}
		nonOptimizedOpts := precompileOpts.SeccompOptions
		nonOptimizedOpts.Optimize = false
		nonOptInsns, _, err := seccomp.BuildProgram(precompileOpts.Rules, nonOptimizedOpts)
		if err != nil {
			return fmt.Errorf("cannot build seccomp program with optimizations disabled: %w", err)
		}
		nonOptimizedOffsets = getVarOffsets(instructionsToUint32Slice(nonOptInsns), values)
		return nil
	}

	for varName := range values {
		if len(varOffsets[varName]) == 0 {
			// If the variable doesn't show up in the optimized program but does
			// show up in the non-optimized program, then it is not unused.
			// It is being optimized away, e.g. as a result of being OR'd with a
			// `MatchAll` rule.
			// Only report an error if the variable shows up in neither optimized
			// nor non-optimized bytecode.
			if err := computeNonOptimizedOffsets(); err != nil {
				return Program{}, fmt.Errorf("cannot compute variable offsets for the non-optimized version of the program: %v", err)
			}
			if len(nonOptimizedOffsets[varName]) == 0 {
				return Program{}, fmt.Errorf("var %q does not show up in the BPF bytecode", varName)
			}
			// We set the offset slice for this variable to a nil slice, so that
			// it gets properly serialized (as opposed to omitted entirely) in the
			// generated Go code.
			varOffsets[varName] = nil
		}
	}
	return Program{
		Name:       name,
		Bytecode32: bytecode32,
		VarOffsets: varOffsets,
	}, nil
}

// getVarOffsets returns the uint32-based offsets at which the values of each
// variable in `values` shows up.
func getVarOffsets(bytecode32 []uint32, values Values) map[string][]int {
	varOffsets := make(map[string][]int, len(values))
	for varName, value := range values {
		for i, v := range bytecode32 {
			if v == value {
				varOffsets[varName] = append(varOffsets[varName], i)
			}
		}
	}
	return varOffsets
}

// Expr renders a Go expression encoding this `Program`.
// It is used when embedding a precompiled `Program` into a Go library file.
// `pkgName` is the package name under which the precompiledseccomp package is
// imported.
func (program Program) Expr(indentPrefix, pkgName string) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s.Program{\n", pkgName))
	sb.WriteString(fmt.Sprintf("%s\tName: %q,\n", indentPrefix, program.Name))
	sb.WriteString(fmt.Sprintf("%s\tBytecode32: []uint32{\n", indentPrefix))
	for _, v := range program.Bytecode32 {
		sb.WriteString(fmt.Sprintf("%s\t\t0x%08x,\n", indentPrefix, v))
	}
	sb.WriteString(fmt.Sprintf("%s\t},\n", indentPrefix))
	sb.WriteString(fmt.Sprintf("%s\tVarOffsets: map[string][]int{\n", indentPrefix))
	varNames := make([]string, 0, len(program.VarOffsets))
	for varName := range program.VarOffsets {
		varNames = append(varNames, varName)
	}
	sort.Strings(varNames)
	for _, varName := range varNames {
		if len(program.VarOffsets[varName]) == 0 {
			sb.WriteString(fmt.Sprintf("%s\t\t%q: nil,\n", indentPrefix, varName))
			continue
		}
		sb.WriteString(fmt.Sprintf("%s\t\t%q: []int{\n", indentPrefix, varName))
		for _, v := range program.VarOffsets[varName] {
			sb.WriteString(fmt.Sprintf("%s\t\t\t%d,\n", indentPrefix, v))
		}
		sb.WriteString(fmt.Sprintf("%s\t\t},\n", indentPrefix))
	}
	sb.WriteString(fmt.Sprintf("%s\t},\n", indentPrefix))
	sb.WriteString(fmt.Sprintf("%s}", indentPrefix))
	return sb.String()
}

// RenderInstructions builds the set of precompiled BPF instructions,
// replacing the variables with their values as given in `values`.
// This must be called with the exact same set of variable names as was used
// during `Precompile`.
func (program Program) RenderInstructions(values Values) ([]bpf.Instruction, error) {
	if len(values) != len(program.VarOffsets) {
		return nil, fmt.Errorf("called with inconsistent vars: got %v expected %v", values, program.VarOffsets)
	}
	for varName, value := range values {
		offsets, found := program.VarOffsets[varName]
		if !found {
			return nil, fmt.Errorf("var %q was not defined in precompiled instructions (defined: %v)", varName, program.VarOffsets)
		}
		for _, offset := range offsets {
			program.Bytecode32[offset] = value
		}
	}
	return uint32SliceToInstructions(program.Bytecode32)
}

// instructionsToUint32Slice converts a slice of BPF instructions into a slice
// of uint32s containing the same binary data.
func instructionsToUint32Slice(insns []bpf.Instruction) []uint32 {
	bytecode := bpf.ToBytecode(insns)
	bytecode32 := make([]uint32, len(bytecode)/4)
	for i := 0; i < len(bytecode); i += 4 {
		bytecode32[i/4] = binary.NativeEndian.Uint32(bytecode[i : i+4])
	}
	return bytecode32
}

// uint32SliceToInstructions converts a slice of uint32s into a slice of
// BPF instructions containing the same binary data.
func uint32SliceToInstructions(bytecode32 []uint32) ([]bpf.Instruction, error) {
	bytecode := make([]byte, len(bytecode32)*4)
	for i, v := range bytecode32 {
		binary.NativeEndian.PutUint32(bytecode[i*4:], v)
	}
	return bpf.ParseBytecode(bytecode)
}

// Registration outputs Go code that registers this programs in a
// `map[string]Program` variable named `programsMapVarName` which maps
// programs names to their `Program` struct.
// It is used when embedding precompiled programs into a Go library file.
func (program Program) Registration(indentPrefix, pkgName, programsMapVarName string) string {
	return fmt.Sprintf("%s%s[%q] = %s\n", indentPrefix, programsMapVarName, program.Name, program.Expr(indentPrefix, pkgName))
}
