// Copyright 2020 The gVisor Authors.
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

// Package checkescape allows recursive escape analysis for hot paths.
//
// The analysis tracks multiple types of escapes, in two categories. First,
// 'hard' escapes are explicit allocations. Second, 'soft' escapes are
// interface dispatches or dynamic function dispatches; these don't necessarily
// escape but they *may* escape. The analysis is capable of making assertions
// recursively: soft escapes cannot be analyzed in this way, and therefore
// count as escapes for recursive purposes.
//
// The different types of escapes are as follows, with the category in
// parentheses:
//
//	heap:      A direct allocation is made on the heap (hard).
//	builtin:   A call is made to a built-in allocation function (hard).
//	stack:     A possible stack split in the function or a runtime helper (soft).
//	interface: A call is made via an interface which *may* escape (soft).
//	dynamic:   A dynamic function is dispatched which *may* escape (soft).
//
// To the use the package, annotate a function-level comment with either the
// line "// +checkescape" or "// +checkescape:OPTION[,OPTION]". In the second
// case, the OPTION field is either a type above, or one of:
//
//	local: Only examines local operations for the selected escape reasons.
//	all: All the escapes are included.
//	hard: All hard escapes are included.
//
// If the "// +checkescape" annotation is provided, this is equivalent to
// provided the local and hard options.
//
// Some examples of this syntax are:
//
// +checkescape:all               - Analyzes for all escapes in this function and all calls.
// +checkescape:local,hard        - Analyzes only for local hard escapes.
// +checkescape:heap              - Only analyzes for heap escapes.
// +checkescape:interface,dynamic - Only checks for dynamic calls and interface calls.
// +checkescape                   - Does the same as +checkescape:local,hard.
//
// Note that all of the above can be inverted by using +mustescape. The
// +checkescape keyword will ensure failure if the class of escape occurs,
// whereas +mustescape will fail if the given class of escape does not occur.
//
// Local exemptions can be made by a comment of the form "// escapes: reason."
// This must appear on the line of the escape and will also apply to callers of
// the function as well (for non-local escape analysis).
//
// Instructions are analyzed for their possible effects before compiled code is
// used to rule out eliminated calls. Generic declarations are analyzed for all
// permitted type arguments, including instantiations compiled only by importing
// packages. Their archives cannot prove that allocations or compiler-generated
// calls were eliminated. Operations whose implementation cannot be established
// from the type constraints count as dynamic escapes; possible boxing and
// conversion allocations also count as heap escapes. Materialized generic locals
// conservatively count as heap allocations, since larger type arguments can
// exceed the compiler's stack-allocation limit.
// An explicit go:nosplit directive rules out only the declaration's own
// stack-splitting prologue.
package checkescape

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"
	"gvisor.dev/gvisor/tools/nogo/flags"
)

const (
	// magic is the magic annotation.
	magic = "// +checkescape"

	// Bad versions of `magic` observed in the wilderness of the codebase.
	badMagicNoSpace = "//+checkescape"
	badMagicPlural  = "// +checkescapes"

	// magicParams is the magic annotation with specific parameters.
	magicParams = magic + ":"

	// testMagic is the test magic annotation (parameters required).
	testMagic = "// +mustescape:"

	// exempt is the exemption annotation.
	exempt = "// escapes"
)

// EscapeReason is an escape reason.
//
// This is a simple enum.
type EscapeReason int

const (
	allocation EscapeReason = iota
	builtin
	interfaceInvoke
	dynamicCall
	stackSplit
	unknownPackage
	reasonCount // Count for below.
)

// String returns the string for the EscapeReason.
//
// Note that this also implicitly defines the reverse string -> EscapeReason
// mapping, which is the word before the colon (computed below).
func (e EscapeReason) String() string {
	switch e {
	case interfaceInvoke:
		return "interface: call to potentially allocating function"
	case unknownPackage:
		return "unknown: no package information available"
	case allocation:
		return "heap: explicit allocation"
	case builtin:
		return "builtin: call to potentially allocating builtin"
	case dynamicCall:
		return "dynamic: call to potentially allocating function"
	case stackSplit:
		return "stack: possible split in function or runtime helper"
	default:
		panic(fmt.Sprintf("unknown reason: %d", e))
	}
}

var hardReasons = []EscapeReason{
	allocation,
	builtin,
}

var softReasons = []EscapeReason{
	interfaceInvoke,
	unknownPackage,
	dynamicCall,
	stackSplit,
}

var allReasons = append(hardReasons, softReasons...)

var escapeTypes = func() map[string]EscapeReason {
	result := make(map[string]EscapeReason)
	for _, r := range allReasons {
		parts := strings.Split(r.String(), ":")
		result[parts[0]] = r // Key before ':'.
	}
	return result
}()

// objdumpAnalyzer accepts the objdump parameter.
type objdumpAnalyzer struct {
	analysis.Analyzer
}

// Run implements nogo.binaryAnalyzer.Run.
func (ob *objdumpAnalyzer) Run(pass *analysis.Pass, binary io.Reader) (any, error) {
	return run(pass, binary)
}

// Legacy implements nogo.analyzer.Legacy.
func (ob *objdumpAnalyzer) Legacy() *analysis.Analyzer {
	return &ob.Analyzer
}

// Analyzer includes specific results.
var Analyzer = &objdumpAnalyzer{
	Analyzer: analysis.Analyzer{
		Name:      "checkescape",
		Doc:       "escape analysis checks based on +checkescape annotations",
		Run:       nil, // Must be invoked via Run above.
		Requires:  []*analysis.Analyzer{buildssa.Analyzer},
		FactTypes: []analysis.Fact{(*Escapes)(nil)},
	},
}

// LinePosition is a low-resolution token.Position.
//
// This is used to match against possible exemptions placed in the source.
type LinePosition struct {
	Filename string
	Line     int
}

// String implements fmt.Stringer.String.
func (e LinePosition) String() string {
	return fmt.Sprintf("%s:%d", e.Filename, e.Line)
}

// Simplified returns the simplified name.
func (e LinePosition) Simplified() string {
	return fmt.Sprintf("%s:%d", filepath.Base(e.Filename), e.Line)
}

// CallSite is a single call site.
//
// These can be chained.
type CallSite struct {
	LocalPos token.Pos
	Resolved LinePosition
}

// IsValid indicates whether the CallSite is valid or not.
func (cs *CallSite) IsValid() bool {
	return cs.LocalPos.IsValid()
}

// Escapes is a collection of escapes.
//
// We record at most one escape for each reason, but record the number of
// escapes that were omitted.
//
// This object should be used to summarize all escapes for a single line (local
// analysis) or a single function (package facts).
//
// All fields are exported for gob.
type Escapes struct {
	CallSites [reasonCount][]CallSite
	Details   [reasonCount]string
	Omitted   [reasonCount]int
}

// AFact implements analysis.Fact.AFact.
func (*Escapes) AFact() {}

// add is called by Add and Merge.
func (es *Escapes) add(r EscapeReason, detail string, omitted int, callSites ...CallSite) {
	if es.CallSites[r] != nil {
		// We will either be replacing the current escape or dropping
		// the added one. Either way, we increment omitted by the
		// appropriate amount.
		es.Omitted[r]++
		// If the callSites in the other is only a single element, then
		// we will universally favor this. This provides the cleanest
		// set of escapes to summarize, and more importantly: if there
		if len(es.CallSites) == 1 || len(callSites) != 1 {
			return
		}
	}
	es.Details[r] = detail
	es.CallSites[r] = callSites
	es.Omitted[r] += omitted
}

// Add adds a single escape.
func (es *Escapes) Add(r EscapeReason, detail string, callSites ...CallSite) {
	es.add(r, detail, 0, callSites...)
}

// IsEmpty returns true iff this Escapes is empty.
func (es *Escapes) IsEmpty() bool {
	for _, cs := range es.CallSites {
		if cs != nil {
			return false
		}
	}
	return true
}

// Filter filters out all escapes except those matches the given reasons.
//
// If local is set, then non-local escapes will also be filtered.
func (es *Escapes) Filter(reasons []EscapeReason, local bool) {
FilterReasons:
	for r := EscapeReason(0); r < reasonCount; r++ {
		for i := 0; i < len(reasons); i++ {
			if r == reasons[i] {
				continue FilterReasons
			}
		}
		// Zap this reason.
		es.CallSites[r] = nil
		es.Details[r] = ""
		es.Omitted[r] = 0
	}
	if !local {
		return
	}
	for r := EscapeReason(0); r < reasonCount; r++ {
		// Is does meet our local requirement?
		if len(es.CallSites[r]) > 1 {
			es.CallSites[r] = nil
			es.Details[r] = ""
			es.Omitted[r] = 0
		}
	}
}

// MergeWithCall merges these escapes with another.
//
// If callSite is nil, no call is added.
func (es *Escapes) MergeWithCall(other Escapes, callSite CallSite) {
	for r := EscapeReason(0); r < reasonCount; r++ {
		if other.CallSites[r] != nil {
			// Construct our new call chain.
			newCallSites := other.CallSites[r]
			if callSite.IsValid() {
				newCallSites = append([]CallSite{callSite}, newCallSites...)
			}
			// Add (potentially replacing) the underlying escape.
			es.add(r, other.Details[r], other.Omitted[r], newCallSites...)
		}
	}
}

// Reportf will call Reportf for each class of escapes.
func (es *Escapes) Reportf(pass *analysis.Pass) {
	var b bytes.Buffer // Reused for all escapes.
	for r := EscapeReason(0); r < reasonCount; r++ {
		if es.CallSites[r] == nil {
			continue
		}
		b.Reset()
		fmt.Fprintf(&b, "%s ", r.String())
		if es.Omitted[r] > 0 {
			fmt.Fprintf(&b, "(%d omitted) ", es.Omitted[r])
		}
		for _, cs := range es.CallSites[r][1:] {
			fmt.Fprintf(&b, "→ %s ", cs.Resolved.String())
		}
		fmt.Fprintf(&b, "→ %s", es.Details[r])
		pass.Reportf(es.CallSites[r][0].LocalPos, "%s", b.String())
	}
}

// MergeAll merges a sequence of escapes.
func MergeAll(others []Escapes) (es Escapes) {
	for _, other := range others {
		es.MergeWithCall(other, CallSite{})
	}
	return
}

// callTarget preserves whether objdump resolved a call to a named symbol.
// An address or an indirect call cannot establish which operation it implements.
type callTarget struct {
	name     string
	resolved bool
}

type callSet map[callTarget]struct{}

func (calls callSet) String() string {
	names := make([]string, 0, len(calls))
	for target := range calls {
		names = append(names, target.name)
	}
	slices.Sort(names)
	return strings.Join(names, " or ")
}

// callKind identifies compiler lowerings whose calls can be distinguished from
// unrelated calls on the same source line. Unknown targets remain conservative.
type callKind int

const (
	anyCall callKind = iota
	implicitCall
	interfaceBoxing
	stringConversion
	pointerConversion
	allocationCall
	sliceAllocation
	builtinAllocation
	sliceGrowth
	slicePromotion
	mapCall
	stackGrowth
)

func (calls callSet) forKind(kind callKind) callSet {
	if kind == anyCall {
		return calls
	}
	filtered := make(callSet)
	for target := range calls {
		matches := !target.resolved
		switch kind {
		case implicitCall:
			// Implicit operators call runtime helpers or generated type
			// algorithms, not user functions. Explicit calls are analyzed
			// separately through SSA. For example, composite equality uses
			// runtime.memequal or a type:.eq function generated by EqFor.
			// https://github.com/golang/go/blob/go1.26.3/src/cmd/compile/internal/reflectdata/alg.go#L645-L652
			matches = matches || strings.HasPrefix(target.name, "runtime.") || strings.HasPrefix(target.name, "type:")
		case allocationCall, sliceAllocation, builtinAllocation:
			// SSA Alloc lowers to newobject or a specialized mallocgc helper.
			// Do not mistake an unrelated builtin on its line for heap storage.
			// https://github.com/golang/go/blob/go1.26.3/src/cmd/compile/internal/ssagen/ssa.go#L864-L876
			matches = matches || target.name == "runtime.newobject" || strings.HasPrefix(target.name, "runtime.mallocgc")
			if kind == sliceAllocation {
				matches = matches || strings.HasPrefix(target.name, "runtime.makeslice")
			}
			if kind == builtinAllocation {
				// make/new are SSA constructors, not language builtin calls.
				// A stack-allocated map can still call nonallocating runtime.rand.
				// https://github.com/golang/go/blob/go1.26.3/src/cmd/compile/internal/walk/builtin.go
				matches = matches || strings.HasPrefix(target.name, "runtime.makemap") ||
					strings.HasPrefix(target.name, "runtime.makechan")
			}
		case sliceGrowth:
			// Append can use a stack buffer or a no-alias growth variant.
			// https://github.com/golang/go/blob/go1.26.3/src/cmd/compile/internal/ssagen/ssa.go#L4062-L4080
			matches = matches || strings.HasPrefix(target.name, "runtime.growslice")
		case slicePromotion:
			// This operation is compiler-inserted, with no owning SSA node.
			// Require positive evidence rather than turning unrelated unknown
			// calls into allocations. SSA handles those calls independently.
			// https://github.com/golang/go/blob/go1.26.3/src/cmd/compile/internal/ssagen/ssa.go#L4221-L4236
			matches = target.resolved && strings.HasPrefix(target.name, "runtime.moveSlice")
		case mapCall:
			matches = matches || strings.HasPrefix(target.name, "runtime.mapaccess") ||
				strings.HasPrefix(target.name, "runtime.mapassign") ||
				strings.HasPrefix(target.name, "runtime.mapdelete") ||
				target.name == "runtime.mapclear" || target.name == "runtime.mapIterStart" || target.name == "runtime.mapIterNext"
		case stackGrowth:
			matches = matches || target.name == "runtime.morestack" || target.name == "runtime.morestack_noctxt" || target.name == "runtime.morestackc"
		case interfaceBoxing:
			// walk.dataWord emits these after inlining, including for FIPS
			// constants that cannot use readonly data. I2I is different.
			// https://github.com/golang/go/blob/go1.26.3/src/cmd/compile/internal/walk/convert.go#L366-L397
			matches = matches || strings.HasPrefix(target.name, "runtime.convT")
		case stringConversion:
			// Literal []byte conversions may allocate an array; concatenation
			// can be combined with conversion. Other forms use string helpers.
			// https://github.com/golang/go/blob/go1.26.3/src/cmd/compile/internal/walk/convert.go#L259-L363
			// https://github.com/golang/go/blob/go1.26.3/src/cmd/compile/internal/ssagen/ssa.go#L864-L876
			switch target.name {
			case "runtime.stringtoslicebyte", "runtime.stringtoslicerune",
				"runtime.slicebytetostring", "runtime.slicebytetostringtmp",
				"runtime.slicerunetostring", "runtime.intstring", "runtime.newobject":
				matches = true
			}
			matches = matches || strings.HasPrefix(target.name, "runtime.concatbyte") || strings.HasPrefix(target.name, "runtime.mallocgc")
		case pointerConversion:
			// uintptr-to-pointer arithmetic and unsafe-to-typed alignment checks.
			// https://github.com/golang/go/blob/go1.26.3/src/cmd/compile/internal/walk/convert.go#L503-L536
			// https://github.com/golang/go/blob/go1.26.3/src/cmd/compile/internal/ssagen/ssa.go#L3187-L3190
			matches = matches || strings.HasPrefix(target.name, "runtime.checkptr")
		}
		if matches {
			filtered[target] = struct{}{}
		}
	}
	return filtered
}

// loadObjdump reads the objdump output.
//
// This records compiled source lines and their calls. It is used to rule out
// operations that the compiler eliminated or implemented without a call, such
// as an allocation placed on the stack.
//
// Note that the map uses <basename.go>:<line> because that is all that is
// provided in the objdump format. Since this is all local, it is sufficient.
func loadObjdump(binary io.Reader) (map[string]callSet, error) {
	// Do we have a binary? If it's missing, then the nil will simply be
	// plumbed all the way down here.
	if binary == nil {
		return nil, fmt.Errorf("no binary provided")
	}

	// Construct & start our command. The 'go tool objdump' command
	// requires a seekable input passed on the command line. Therefore, we
	// may need to generate a temporary file here.
	input, ok := binary.(*os.File)
	if ok {
		// Ensure that the file is seekable and that the offset is
		// zero, since we can't control that.
		if offset, err := input.Seek(0, io.SeekCurrent); err != nil || offset != 0 {
			ok = false // Not usable.
		}
	}
	if !ok {
		// Copy to a temporary path.
		f, err := os.CreateTemp("", "")
		if err != nil {
			return nil, fmt.Errorf("unable to create temp file: %w", err)
		}
		// Ensure the file is deleted.
		defer os.Remove(f.Name())
		// Populate the file contents.
		if _, err := io.Copy(f, binary); err != nil {
			return nil, fmt.Errorf("unable to populate temp file: %w", err)
		}
		// Seek to the beginning.
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return nil, fmt.Errorf("unable to seek in temp file: %w", err)
		}
		input = f
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Execute go tool objdump given the input.
	cmd := exec.CommandContext(ctx, flags.Go, "tool", "objdump", input.Name())
	if goroot, ok := os.LookupEnv("GOROOT"); ok && strings.HasPrefix(goroot, "bazel-out/") {
		// Under Bazel, our nogo machinery sets GOROOT to a stdlib output tree,
		// which does not include the prebuilt objdump tool. Some Go versions
		// may build objdump on-demand via `go tool objdump`, which requires a
		// writable build cache.
		//
		// See https://go.dev/issue/71867 and
		// https://github.com/bazel-contrib/rules_go/issues/4535.
		cacheDirRel := filepath.Join("bazel-out", ".checkescape-gocache")
		if err := os.MkdirAll(cacheDirRel, 0755); err != nil {
			return nil, fmt.Errorf("unable to create build cache dir %q: %w", cacheDirRel, err)
		}
		// GOCACHE must be an absolute path.
		cacheDirAbs, err := filepath.Abs(cacheDirRel)
		if err != nil {
			return nil, fmt.Errorf("unable to get absolute path of build cache dir %q: %w", cacheDirRel, err)
		}
		env := os.Environ()
		env = slices.DeleteFunc(env, func(kv string) bool {
			return strings.HasPrefix(kv, "GOROOT=") || strings.HasPrefix(kv, "GOCACHE=")
		})
		env = append(env, "GOCACHE="+cacheDirAbs)
		cmd.Env = env
	}
	pipeOut, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("unable to get objdump stdout pipe: %w", err)
	}
	defer pipeOut.Close()
	var bufErr bytes.Buffer
	cmd.Stderr = &bufErr
	if startErr := cmd.Start(); startErr != nil {
		return nil, fmt.Errorf("unable to start objdump: %w: %s", startErr, bufErr.String())
	}

	// Identify calls by address or name. Note that the list of allowed addresses
	// -- not the list of allowed function names -- is also constructed
	// dynamically below, as we encounter the addresses. This is because some of
	// the functions (duffzero) may have jump targets in the middle of the
	// function itself.
	funcsAllowed := map[string]struct{}{
		"runtime.duffzero":       {},
		"runtime.duffcopy":       {},
		"runtime.racefuncenter":  {},
		"runtime.gcWriteBarrier": {},
		"runtime.retpolineAX":    {},
		"runtime.retpolineBP":    {},
		"runtime.retpolineBX":    {},
		"runtime.retpolineCX":    {},
		"runtime.retpolineDI":    {},
		"runtime.retpolineDX":    {},
		"runtime.retpolineR10":   {},
		"runtime.retpolineR11":   {},
		"runtime.retpolineR12":   {},
		"runtime.retpolineR13":   {},
		"runtime.retpolineR14":   {},
		"runtime.retpolineR15":   {},
		"runtime.retpolineR8":    {},
		"runtime.retpolineR9":    {},
		"runtime.retpolineSI":    {},
		"runtime.stackcheck":     {},
		"runtime.settls":         {},
	}
	// addrsAllowed lists every address that can be jumped to within the
	// funcsAllowed functions.
	addrsAllowed := make(map[string]struct{})

	// Build the map.
	nextFunc := "" // For funcsAllowed.
	m := make(map[string]callSet)
	s := bufio.NewScanner(pipeOut)
	for s.Scan() {
		line := s.Text()
		fields := strings.Fields(line)

		// Is this an "allowed" function definition? If so, record every address of
		// the function body.
		if len(fields) >= 2 && fields[0] == "TEXT" {
			nextFunc = strings.TrimSuffix(fields[1], "(SB)")
			if _, ok := funcsAllowed[nextFunc]; !ok {
				nextFunc = "" // Don't record addresses.
			}
		}
		if nextFunc != "" && len(fields) > 2 {
			// We're inside an allowed function. Save the given address (in hex form,
			// as it appears).
			addrsAllowed[fields[1]] = struct{}{}
		}

		// We recognize lines corresponding to actual code (not the
		// symbol name or other metadata) and annotate them if they
		// correspond to an explicit CALL instruction. We assume that
		// the lack of a CALL for a given line is evidence that escape
		// analysis has eliminated an allocation.
		//
		// Lines look like this (including the first space):
		//  gohacks_unsafe.go:33  0xa39                   488b442408              MOVQ 0x8(SP), AX
		if len(fields) >= 4 && line[0] == ' ' {
			site := fields[0]
			// An empty entry distinguishes compiled code without calls from
			// source that is absent from this archive, including RET-only bodies.
			if _, ok := m[site]; !ok {
				m[site] = nil
			}
			if len(fields) < 5 || !strings.Contains(fields[3], "CALL") {
				continue
			}
			target := strings.TrimSuffix(fields[4], "(SB)")
			resolved := strings.HasSuffix(fields[4], "(SB)")
			target, err := fixOffset(fields, target)
			if err != nil {
				return nil, err
			}

			// Object files may print an address placeholder followed by the
			// call's relocation. Retain its symbol when available, both for
			// diagnostics and to identify calls implementing interface boxing.
			for _, field := range fields[5:] {
				for _, kind := range []string{"]R_CALL:", "]R_CALLARM64:"} {
					if _, symbol, ok := strings.Cut(field, kind); ok && !strings.Contains(symbol, "+") {
						target = strings.TrimSuffix(symbol, "<1>")
						resolved = true
					}
				}
			}

			// Ignore strings containing allowed functions.
			if _, ok := funcsAllowed[target]; ok {
				continue
			}
			if _, ok := addrsAllowed[target]; ok {
				continue
			}
			if len(fields) > 5 {
				// This may be a future relocation. Some
				// objdump versions describe this differently.
				// If it contains any of the functions allowed
				// above as a string, we let it go.
				softTarget := strings.Join(fields[5:], " ")
				if func() bool {
					for name := range funcsAllowed {
						if strings.Contains(softTarget, name) {
							return true
						}
					}
					return false
				}() {
					continue
				}
			}

			calls := m[site]
			if calls == nil {
				calls = make(callSet)
				m[site] = calls
			}
			calls[callTarget{name: target, resolved: resolved}] = struct{}{}
		}
	}
	if err := s.Err(); err != nil {
		return nil, err
	}

	// Ensure that the command has finished successfully. Note that even if
	// we parse the first few lines correctly, and early exit could
	// indicate that the dump was incomplete and we could be missed some
	// escapes that would have appeared. We need to force failure.
	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("error running %q: %s (%s)", cmd, err, bufErr.String())
	}

	// Zap any accidental false positives.
	for _, calls := range m {
		for call := range calls {
			if _, ok := addrsAllowed[call.name]; ok {
				delete(calls, call)
			}
		}
	}

	return m, nil
}

// poser is a type that implements Pos.
type poser interface {
	Pos() token.Pos
}

// findReasons extracts reasons from the function.
func findReasons(pass *analysis.Pass, fdecl *ast.FuncDecl) ([]EscapeReason, bool, map[EscapeReason]bool) {
	// Is there a comment?
	if fdecl.Doc == nil {
		return nil, false, nil
	}
	var (
		reasons     []EscapeReason
		local       bool
		testReasons = make(map[EscapeReason]bool) // reason -> local?
	)
	// Scan all lines.
	found := false
	for _, c := range fdecl.Doc.List {
		if strings.HasPrefix(c.Text, badMagicNoSpace) || strings.HasPrefix(c.Text, badMagicPlural) {
			pass.Reportf(fdecl.Pos(), "misspelled checkescape prefix: please use %q instead", magic)
			continue
		}
		// Does the comment contain a +checkescape line?
		if !strings.HasPrefix(c.Text, magic) && !strings.HasPrefix(c.Text, testMagic) {
			continue
		}
		if c.Text == magic {
			// Default: hard reasons, local only.
			reasons = hardReasons
			local = true
		} else if strings.HasPrefix(c.Text, magicParams) {
			// Extract specific reasons.
			types := strings.Split(c.Text[len(magicParams):], ",")
			found = true // For below.
			for i := 0; i < len(types); i++ {
				switch types[i] {
				case "local":
					// Limit search to local escapes.
					local = true
				case "all":
					// Append all reasons.
					reasons = append(reasons, allReasons...)
				case "hard":
					// Append all hard reasons.
					reasons = append(reasons, hardReasons...)
				default:
					r, ok := escapeTypes[types[i]]
					if !ok {
						// This is not a valid escape reason.
						pass.Reportf(fdecl.Pos(), "unknown reason: %v", types[i])
						continue
					}
					reasons = append(reasons, r)
				}
			}
		} else if strings.HasPrefix(c.Text, testMagic) {
			types := strings.Split(c.Text[len(testMagic):], ",")
			local := false
			for i := 0; i < len(types); i++ {
				if types[i] == "local" {
					local = true
				} else {
					r, ok := escapeTypes[types[i]]
					if !ok {
						// This is not a valid escape reason.
						pass.Reportf(fdecl.Pos(), "unknown reason: %v", types[i])
						continue
					}
					if v, ok := testReasons[r]; ok && v {
						// Already registered as local.
						continue
					}
					testReasons[r] = local
				}
			}
		}
	}
	if len(reasons) == 0 && found {
		// A magic annotation was provided, but no reasons.
		pass.Reportf(fdecl.Pos(), "no reasons provided")
	}
	return reasons, local, testReasons
}

// isGeneric includes closures in generic functions, whose compilation also
// depends on their enclosing function's type arguments.
func isGeneric(fn *ssa.Function) bool {
	for ; fn != nil; fn = fn.Parent() {
		if fn.TypeParams().Len() > 0 || fn.Signature.RecvTypeParams().Len() > 0 {
			return true
		}
	}
	return false
}

// genericCallee finds the declaration whose facts describe fn. Besides generic
// instantiations, SSA creates thunks for method expressions. Only a thunk that
// forwards its receiver and arguments unchanged is equivalent to the declared
// method: receiver adaptations may introduce a separate compiler wrapper whose
// stack behavior is not covered by the method's nosplit directive.
// Go reuses the method's instantiation wrapper when the receiver matches:
// https://github.com/golang/go/blob/go1.26.3/src/cmd/compile/internal/noder/reader.go#L2913
func genericCallee(fn *ssa.Function) *ssa.Function {
	if origin := fn.Origin(); origin != nil {
		return origin
	}
	obj, ok := fn.Object().(*types.Func)
	if !ok || obj.Origin() == obj || fn.Signature.Recv() != nil || len(fn.Blocks) != 1 {
		return fn
	}
	recv := obj.Type().(*types.Signature).Recv()
	if recv == nil || len(fn.Params) == 0 || !types.Identical(fn.Params[0].Type(), recv.Type()) {
		return fn
	}
	var call *ssa.Call
	var origin *ssa.Function
	for _, inst := range fn.Blocks[0].Instrs {
		switch inst := inst.(type) {
		case *ssa.Call:
			if call != nil || len(inst.Call.Args) != len(fn.Params) {
				return fn
			}
			for i, arg := range inst.Call.Args {
				if arg != fn.Params[i] {
					return fn
				}
			}
			callee := inst.Call.StaticCallee()
			if callee == nil {
				return fn
			}
			origin = callee.Origin()
			if origin == nil || origin.Object() != obj.Origin() {
				return fn
			}
			call = inst
		case *ssa.Extract:
			if call == nil || inst.Tuple != call {
				return fn
			}
		case *ssa.Return, *ssa.DebugRef:
		default:
			return fn
		}
	}
	if origin != nil {
		return origin
	}
	return fn
}

// allTypes proves a property for every type permitted by typ. A union requires
// every term to satisfy the property; an intersection needs only one embedded
// restriction that proves it. This is a sufficient proof, not type-set expansion.
func allTypes(typ types.Type, property func(types.Type) bool) bool {
	typ = types.Unalias(typ)
	if param, ok := typ.(*types.TypeParam); ok {
		return allTypes(param.Constraint(), property)
	}
	switch typ := typ.Underlying().(type) {
	case *types.Union:
		for i := 0; i < typ.Len(); i++ {
			if !allTypes(typ.Term(i).Type(), property) {
				return false
			}
		}
		return true
	case *types.Interface:
		for i := 0; i < typ.NumEmbeddeds(); i++ {
			if allTypes(typ.EmbeddedType(i), property) {
				return true
			}
		}
		return false
	default:
		return property(typ)
	}
}

func isNumeric(typ types.Type) bool {
	basic, ok := typ.(*types.Basic)
	return ok && basic.Info()&types.IsNumeric != 0
}

func isScalar(typ types.Type) bool {
	switch typ.(type) {
	case *types.Basic, *types.Pointer, *types.Chan:
		return true
	default:
		return false
	}
}

func isDirectInterfaceValue(typ types.Type) bool {
	switch typ := typ.(type) {
	case *types.Pointer, *types.Chan, *types.Map, *types.Signature:
		return true // Already represented by a pointer.
	case *types.Basic:
		return typ.Kind() == types.UnsafePointer
	default:
		return false
	}
}

// run performs the analysis.
func run(pass *analysis.Pass, binary io.Reader) (any, error) {
	// Note that if this analysis fails, then we don't actually
	// fail the analyzer itself. We simply report every possible
	// escape. In most cases this will work just fine.
	calls, callsErr := loadObjdump(binary)
	allEscapes := make(map[string][]Escapes)
	mergedEscapes := make(map[string]Escapes)
	linePosition := func(inst, parent poser) LinePosition {
		p := pass.Fset.Position(inst.Pos())
		if (p.Filename == "" || p.Line == 0) && parent != nil {
			p = pass.Fset.Position(parent.Pos())
		}
		return LinePosition{
			Filename: p.Filename,
			Line:     p.Line,
		}
	}
	// Next has no independent source position. The Range instruction owns
	// both iterator initialization and advancement, including exemptions.
	position := func(inst poser) token.Pos {
		if next, ok := inst.(*ssa.Next); ok {
			return next.Iter.Pos()
		}
		return inst.Pos()
	}
	callSite := func(inst ssa.Instruction) CallSite {
		pos := position(inst)
		if !pos.IsValid() {
			pos = inst.Parent().Pos()
		}
		p := pass.Fset.Position(pos)
		return CallSite{
			LocalPos: pos,
			Resolved: LinePosition{Filename: p.Filename, Line: p.Line},
		}
	}
	var loadFunc func(*ssa.Function) Escapes // Used recursively below.
	loadCallee := func(x *ssa.Function, cs CallSite) (es Escapes) {
		// buildssa represents instantiations as wrappers with no Pkg.
		// Analyze and import facts for the generic declaration instead.
		x = genericCallee(x)
		// Is this a local function? If yes, call the
		// function to load the local function. The
		// local escapes are the escapes found in the
		// local function.
		if x.Pkg != nil && x.Pkg.Pkg == pass.Pkg {
			es.MergeWithCall(loadFunc(x), cs)
			return
		}

		// If this package is the atomic package, the implementation
		// may be replaced by intrinsics that don't have analysis.
		if x.Pkg != nil && x.Pkg.Pkg.Path() == "sync/atomic" {
			return
		}

		// Recursively collect information.
		var funcEscapes Escapes
		obj := x.Object()
		if obj == nil || !pass.ImportObjectFact(obj, &funcEscapes) {
			// If this is the unix or syscall
			// package, and the function is
			// RawSyscall, we can also ignore this
			// case.
			pkgIsUnixOrSyscall := x.Pkg != nil && (x.Pkg.Pkg.Name() == "unix" || x.Pkg.Pkg.Name() == "syscall")
			methodIsRawSyscall := x.Name() == "RawSyscall" || x.Name() == "RawSyscall6"
			if pkgIsUnixOrSyscall && methodIsRawSyscall {
				return
			}

			// Unable to import the dependency; we must
			// declare these as escaping.
			name := x.String()
			if obj != nil {
				name = obj.String()
			}
			message := fmt.Sprintf("no analysis for %q", name)
			es.Add(unknownPackage, message, cs)
			return
		}

		// The escapes of this instruction are the
		// escapes of the called function directly.
		// Note that this may record many escapes.
		es.MergeWithCall(funcEscapes, cs)
		return
	}
	state := pass.ResultOf[buildssa.Analyzer].(*buildssa.SSA)

	// Build the exception list before collecting compiled-operation evidence.
	exemptions := make(map[LinePosition]string)
	// SSA represents constant-capacity make([]T, n, m) as Alloc + Slice.
	// Preserve the typed source operation, not Alloc's descriptive Comment.
	// https://github.com/golang/tools/blob/v0.45.0/go/ssa/builder.go#L343-L353
	// https://github.com/golang/tools/blob/v0.45.0/go/ssa/builder.go#L715-L719
	makePositions := make(map[token.Pos]struct{})
	for _, f := range pass.Files {
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			id, ok := ast.Unparen(call.Fun).(*ast.Ident)
			if !ok {
				return true
			}
			if obj, ok := pass.TypesInfo.Uses[id].(*types.Builtin); ok && obj.Name() == "make" {
				makePositions[call.Lparen] = struct{}{}
			}
			return true
		})
		for _, cg := range f.Comments {
			for _, c := range cg.List {
				p := pass.Fset.Position(c.Slash)
				if strings.HasPrefix(strings.ToLower(c.Text), exempt) {
					exemptions[LinePosition{Filename: p.Filename, Line: p.Line}] = c.Text[len(exempt):]
				}
			}
		}
	}

	// A nil entry means that the function has no usable source body. Keep
	// covered call-free lines distinct from an absent compiled source span.
	bodyCalls := make(map[*ssa.Function]map[CallSite]callSet)
	functionCalls := func(fn *ssa.Function) map[CallSite]callSet {
		if calls, ok := bodyCalls[fn]; ok {
			return calls
		}
		bodyCalls[fn] = nil
		if fn == nil {
			return nil
		}
		syntax := fn.Syntax()
		switch syntax := syntax.(type) {
		case *ast.FuncDecl:
			if syntax.Body == nil {
				return nil
			}
		case *ast.FuncLit:
		default:
			return nil
		}
		start := pass.Fset.Position(syntax.Pos())
		end := pass.Fset.Position(syntax.End())
		file := pass.Fset.File(syntax.Pos())
		if file == nil || start.Filename != file.Name() || start.Filename != end.Filename || start.Line == 0 || end.Line < start.Line || end.Line > file.LineCount() {
			return nil
		}
		// A closure is analyzed as its own SSA function. Do not borrow calls
		// from its body for the enclosing function. Objdump has only line
		// resolution, so shared boundary lines remain conservative.
		nestedLines := make(map[int]struct{})
		ast.Inspect(syntax, func(node ast.Node) bool {
			lit, ok := node.(*ast.FuncLit)
			if !ok || node == syntax {
				return true
			}
			first := pass.Fset.Position(lit.Body.Lbrace)
			last := pass.Fset.Position(lit.Body.Rbrace)
			if first.Filename == start.Filename && last.Filename == start.Filename {
				for line := first.Line + 1; line < last.Line; line++ {
					nestedLines[line] = struct{}{}
				}
			}
			return false
		})
		found := make(map[CallSite]callSet)
		for line := start.Line; line <= end.Line; line++ {
			if _, nested := nestedLines[line]; nested {
				continue
			}
			p := LinePosition{Filename: start.Filename, Line: line}
			if lineCalls, ok := calls[p.Simplified()]; ok {
				found[CallSite{LocalPos: file.LineStart(line), Resolved: p}] = lineCalls
			}
		}
		if len(found) == 0 {
			return nil
		}
		bodyCalls[fn] = found
		return found
	}
	type callEvidence struct {
		detail   string
		site     CallSite
		fromBody bool
	}
	type evidenceKey struct {
		fn   *ssa.Function
		kind callKind
	}
	implicitCalls := make(map[evidenceKey][]callEvidence)
	bodyEvidence := func(fn *ssa.Function, kind callKind) ([]callEvidence, bool) {
		key := evidenceKey{fn: fn, kind: kind}
		if evidence, ok := implicitCalls[key]; ok {
			return evidence, true
		}
		body := functionCalls(fn)
		if body == nil {
			return nil, false
		}
		var evidence []callEvidence
		for site, calls := range body {
			if _, ok := exemptions[site.Resolved]; ok {
				continue
			}
			if calls = calls.forKind(kind); len(calls) != 0 {
				evidence = append(evidence, callEvidence{detail: calls.String(), site: site, fromBody: true})
			}
		}
		slices.SortFunc(evidence, func(a, b callEvidence) int { return cmp.Compare(a.site.LocalPos, b.site.LocalPos) })
		implicitCalls[key] = evidence
		return evidence, true
	}
	compiledCalls := func(inst poser, kind callKind) []callEvidence {
		var fn *ssa.Function
		var cs CallSite
		switch inst := inst.(type) {
		case *ssa.Function:
			fn = inst
			cs = CallSite{LocalPos: fn.Pos(), Resolved: linePosition(fn, fn.Parent())}
		case ssa.Instruction:
			fn = inst.Parent()
			cs = callSite(inst)
		}
		if inst == fn && kind == stackGrowth {
			// An explicit nosplit directive covers the declaration's prologue,
			// including every instantiation. It does not cover called helpers
			// or closures, which have no directive of their own.
			if decl, ok := fn.Syntax().(*ast.FuncDecl); ok && decl.Doc != nil {
				for _, comment := range decl.Doc.List {
					if comment.Text == "//go:nosplit" {
						return nil
					}
				}
			}
		}
		if isGeneric(fn) {
			// A generic body may only be compiled in an importing package.
			// Even when this package instantiates it, other type arguments
			// may produce different code. Absence of a call in this archive
			// therefore cannot establish that an escape was eliminated.
			return []callEvidence{{detail: "(possible in a generic function)", site: cs}}
		}
		if callsErr != nil {
			return []callEvidence{{detail: fmt.Sprintf("(possible, %s)", callsErr), site: cs}}
		}
		if position(inst).IsValid() {
			s := calls[cs.Resolved.Simplified()].forKind(kind)
			if len(s) == 0 {
				return nil
			}
			return []callEvidence{{detail: s.String(), site: cs}}
		}
		// Implicit conversions have no SSA source position. Use the enclosing
		// body, retaining actual helper locations and local exemptions.
		evidence, ok := bodyEvidence(fn, kind)
		if !ok {
			return []callEvidence{{detail: "(possible, no compiled source body)", site: cs}}
		}
		return evidence
	}
	callDetails := func(inst poser) string {
		evidence := compiledCalls(inst, anyCall)
		details := make([]string, 0, len(evidence))
		for _, call := range evidence {
			details = append(details, call.detail)
		}
		return strings.Join(details, " or ")
	}

	// SSA operations and compiler-inserted operations share diagnostic emission.
	emitCalls := func(evidence []callEvidence, reasons []EscapeReason, inst ssa.Instruction) (es Escapes) {
		for _, call := range evidence {
			detail := "compiler-generated call: " + call.detail
			if inst != nil && !call.fromBody {
				detail = fmt.Sprintf("compiler implementation of %q: %s", inst.String(), call.detail)
			}
			for _, reason := range reasons {
				es.Add(reason, detail, call.site)
			}
		}
		return
	}

	analyzeInstruction := func(inst ssa.Instruction) (es Escapes) {
		cs := callSite(inst)
		if _, ok := exemptions[cs.Resolved]; ok {
			return // No escape.
		}
		var from, to types.Type
		reasons := []EscapeReason{dynamicCall}
		kind := implicitCall
		switch x := inst.(type) {
		case *ssa.Call:
			if x.Call.IsInvoke() {
				// This is an interface dispatch. There is no
				// way to know if this is actually escaping or
				// not, since we don't know the underlying
				// type.
				call := callDetails(inst)
				es.Add(interfaceInvoke, call, cs)
				return
			}
			switch x := x.Call.Value.(type) {
			case *ssa.Function:
				return loadCallee(x, cs)
			case *ssa.Builtin:
				switch x.Name() {
				case "append":
					kind, reasons = sliceGrowth, []EscapeReason{builtin}
				case "clear":
					if allTypes(inst.(*ssa.Call).Call.Args[0].Type(), func(typ types.Type) bool {
						_, ok := typ.(*types.Slice)
						return ok
					}) {
						// Slice clearing uses NOSPLIT memclr helpers, including
						// the write-barrier path for pointer elements.
						// https://github.com/golang/go/blob/go1.26.3/src/runtime/mbarrier.go#L425-L430
						return
					}
					kind, reasons = mapCall, []EscapeReason{stackSplit}
				case "delete":
					kind, reasons = mapCall, []EscapeReason{stackSplit}
				case "len", "cap", "real", "imag", "complex", "panic":
					return
				case "min", "max":
					if allTypes(inst.(*ssa.Call).Type(), func(typ types.Type) bool {
						basic, ok := typ.(*types.Basic)
						return ok && basic.Info()&types.IsInteger != 0
					}) {
						return
					}
				}
			default:
				// All dynamic calls are counted as soft
				// escapes. They are similar to interface
				// dispatches. We cannot actually look up what
				// this refers to using static analysis alone.
				call := callDetails(inst)
				es.Add(dynamicCall, call, cs)
				return
			}
		case *ssa.Alloc:
			// SSA's Heap flag does not account for the compiler's size limit,
			// even for a concrete local. Compiled allocator calls distinguish
			// heap storage from stack storage and eliminated allocations.
			kind, reasons = allocationCall, []EscapeReason{allocation}
			if _, ok := makePositions[x.Pos()]; ok {
				kind = sliceAllocation
			}
		case *ssa.MakeSlice:
			kind, reasons = sliceAllocation, []EscapeReason{builtin}
		case *ssa.MakeClosure:
			kind, reasons = allocationCall, []EscapeReason{builtin}
		case *ssa.MakeMap, *ssa.MakeChan:
			kind, reasons = builtinAllocation, []EscapeReason{builtin}
		case *ssa.Lookup:
			kind, reasons = mapCall, []EscapeReason{stackSplit}
		case *ssa.MapUpdate:
			kind, reasons = mapCall, []EscapeReason{builtin, stackSplit}
		case *ssa.Range:
			return // Next owns the range's implicit calls and source position.
		case *ssa.Next:
			if !x.IsString {
				kind, reasons = mapCall, []EscapeReason{stackSplit}
			}
		case *ssa.Phi, *ssa.Extract, *ssa.If, *ssa.Jump, *ssa.Return,
			*ssa.Field, *ssa.FieldAddr, *ssa.Index, *ssa.IndexAddr, *ssa.Slice,
			*ssa.Store, *ssa.SliceToArrayPointer, *ssa.DebugRef:
			return
		case *ssa.ChangeType:
			// SSA may treat a type parameter and an interface with the same
			// underlying constraint as representation-preserving. Concrete
			// instantiations can still need storage for the interface value.
			_, fromTypeParam := types.Unalias(x.X.Type()).(*types.TypeParam)
			_, toTypeParam := types.Unalias(x.Type()).(*types.TypeParam)
			_, toInterface := x.Type().Underlying().(*types.Interface)
			if !fromTypeParam || toTypeParam || !toInterface || allTypes(x.X.Type(), isDirectInterfaceValue) {
				return
			}
			reasons = []EscapeReason{allocation, dynamicCall}
		case *ssa.Panic:
			return // Panic paths, like bounds-check failures, are not checked.
		case *ssa.Go, *ssa.Defer, *ssa.RunDefers:
			// These can call user functions directly, unlike implicit operators.
			kind = anyCall
		case *ssa.UnOp:
			if x.Op != token.ARROW {
				return
			}
		case *ssa.BinOp:
			if x.Op == token.EQL || x.Op == token.NEQ {
				isNil := func(v ssa.Value) bool {
					c, ok := v.(*ssa.Const)
					return ok && c.IsNil()
				}
				// String equality can call memequal, whose amd64 and arm64
				// implementations are NOSPLIT assembly without further calls.
				// https://github.com/golang/go/blob/go1.26.3/src/internal/bytealg/equal_amd64.s
				// https://github.com/golang/go/blob/go1.26.3/src/internal/bytealg/equal_arm64.s
				if isNil(x.X) || isNil(x.Y) || allTypes(x.X.Type(), isScalar) {
					return
				}
			} else if allTypes(x.X.Type(), func(typ types.Type) bool {
				basic, ok := typ.(*types.Basic)
				if !ok {
					return false
				}
				switch x.Op {
				case token.ADD:
					return basic.Info()&types.IsNumeric != 0
				case token.QUO:
					return basic.Info()&types.IsComplex == 0
				default:
					return true
				}
			}) {
				return
			}
			if x.Op == token.ADD { // String concatenation.
				reasons = []EscapeReason{allocation, dynamicCall}
			}
		case *ssa.Convert:
			from, to = x.X.Type(), x.Type()
		case *ssa.MultiConvert:
			from, to = x.X.Type(), x.Type()
		case *ssa.MakeInterface:
			kind = interfaceBoxing
			if allTypes(x.X.Type(), isDirectInterfaceValue) {
				return
			}
			reasons = []EscapeReason{allocation, dynamicCall} // The interface may need storage for its value.
		case *ssa.ChangeInterface:
			if x.Type().Underlying().(*types.Interface).Empty() {
				return // Dropping methods only changes the interface header.
			}
		case *ssa.TypeAssert:
			if allTypes(x.AssertedType, isScalar) {
				return // A concrete type check and copy, excluding its panic path.
			}
		}
		if from != nil {
			if allTypes(from, isNumeric) && allTypes(to, isNumeric) {
				return
			}
			// Converting pointers to addresses is representation-preserving. The
			// reverse conversion can invoke checkptr, so remains conservative.
			pointer := func(typ types.Type) bool {
				_, ok := typ.(*types.Pointer)
				return ok
			}
			unsafePointer := func(typ types.Type) bool {
				basic, ok := typ.(*types.Basic)
				return ok && basic.Kind() == types.UnsafePointer
			}
			uintptrType := func(typ types.Type) bool {
				basic, ok := typ.(*types.Basic)
				return ok && basic.Kind() == types.Uintptr
			}
			if (allTypes(from, pointer) && allTypes(to, unsafePointer)) ||
				(allTypes(from, unsafePointer) && allTypes(to, uintptrType)) {
				return
			}
			// String and slice conversions may need backing storage. Pointer
			// conversions can require checkptr calls, but do not allocate.
			withoutStorage := func(typ types.Type) bool {
				switch typ := typ.(type) {
				case *types.Basic:
					return typ.Info()&types.IsString == 0
				case *types.Slice:
					return false
				default:
					return true
				}
			}
			if !allTypes(from, withoutStorage) || !allTypes(to, withoutStorage) {
				kind, reasons = stringConversion, []EscapeReason{allocation, dynamicCall}
			} else {
				kind = pointerConversion
			}
		}
		return emitCalls(compiledCalls(inst, kind), reasons, inst)
	}

	analyzeBasicBlock := func(block *ssa.BasicBlock) (rval []Escapes) {
		for _, inst := range block.Instrs {
			if es := analyzeInstruction(inst); !es.IsEmpty() {
				rval = append(rval, es)
			}
		}
		return
	}

	loadFunc = func(fn *ssa.Function) Escapes {
		// Is this already available?
		name := fn.RelString(pass.Pkg)
		if es, ok := mergedEscapes[name]; ok {
			return es
		}

		// In the case of a true cycle, we assume that the current
		// function itself has no escapes.
		//
		// When evaluating the function again, the proper escapes will
		// be filled in here.
		allEscapes[name] = nil
		mergedEscapes[name] = Escapes{}

		// Perform the basic analysis.
		var es []Escapes
		if fn.Recover != nil {
			es = append(es, analyzeBasicBlock(fn.Recover)...)
		}
		for _, block := range fn.Blocks {
			es = append(es, analyzeBasicBlock(block)...)
		}

		// The compiler can move append storage to the heap at a later return
		// or assignment, an operation absent from x/tools SSA. Record each
		// known promotion once at its own site, independently of exemptions
		// on originating appends. Generic append effects are already covered
		// conservatively by source analysis.
		// https://github.com/golang/go/blob/go1.26.3/src/cmd/compile/internal/slice/slice.go#L426-L450
		if !isGeneric(fn) {
			promotions, _ := bodyEvidence(fn, slicePromotion)
			es = append(es, emitCalls(promotions, []EscapeReason{builtin}, nil))
		}
		es = append(es, emitCalls(compiledCalls(fn, stackGrowth), []EscapeReason{stackSplit}, nil))

		// Save the result and return.
		//
		// Note that we merge the result when saving to the facts. It
		// doesn't really matter the specific escapes, as long as we
		// have recorded all the appropriate classes of escapes.
		summary := MergeAll(es)
		allEscapes[name] = es
		mergedEscapes[name] = summary
		return summary
	}

	// Complete all local functions.
	for _, fn := range state.SrcFuncs {
		funcEscapes := loadFunc(fn)
		if obj := fn.Object(); obj != nil {
			pass.ExportObjectFact(obj, &funcEscapes)
		}
	}

	// Scan all functions for violations.
	for _, f := range pass.Files {
		// Scan all declarations.
		for _, decl := range f.Decls {
			// Function declaration?
			fdecl, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			// Find all declared reasons.
			reasons, local, testReasons := findReasons(pass, fdecl)

			// Scan for matches.
			fn := pass.TypesInfo.Defs[fdecl.Name].(*types.Func)
			fv := state.Pkg.Prog.FuncValue(fn)
			if fv == nil {
				continue
			}
			name := fv.RelString(pass.Pkg)
			all, allOk := allEscapes[name]
			merged, mergedOk := mergedEscapes[name]
			if !allOk || !mergedOk {
				pass.Reportf(fdecl.Pos(), "internal error: function %s not found.", name)
				continue
			}

			// Filter reasons and report.
			//
			// For the findings, we use all escapes.
			for _, es := range all {
				es.Filter(reasons, local)
				es.Reportf(pass)
			}

			// Scan for test (required) matches.
			//
			// For tests we need only the merged escapes.
			testReasonsFound := make(map[EscapeReason]bool)
			for r := EscapeReason(0); r < reasonCount; r++ {
				if merged.CallSites[r] == nil {
					continue
				}
				// Is this local?
				wantLocal, ok := testReasons[r]
				isLocal := len(merged.CallSites[r]) == 1
				testReasonsFound[r] = isLocal
				if !ok {
					continue
				}
				if isLocal == wantLocal {
					delete(testReasons, r)
				}
			}
			for reason, local := range testReasons {
				// We didn't find the escapes we wanted.
				pass.Reportf(fdecl.Pos(), "%s", fmt.Sprintf("testescapes not found: reason=%s, local=%t", reason, local))
			}
			if len(testReasons) > 0 {
				// Report for debugging.
				merged.Reportf(pass)
			}
		}
	}

	return nil, nil
}
