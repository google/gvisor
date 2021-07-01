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
// 	heap:      A direct allocation is made on the heap (hard).
// 	builtin:   A call is made to a built-in allocation function (hard).
// 	stack:     A stack split as part of a function preamble (soft).
// 	interface: A call is made via an interface which *may* escape (soft).
// 	dynamic:   A dynamic function is dispatched which *may* escape (soft).
//
// To the use the package, annotate a function-level comment with either the
// line "// +checkescape" or "// +checkescape:OPTION[,OPTION]". In the second
// case, the OPTION field is either a type above, or one of:
//
//	local: Escape analysis is limited to local hard escapes only.
//	all: All the escapes are included.
//	hard: All hard escapes are included.
//
// If the "// +checkescape" annotation is provided, this is equivalent to
// provided the local and hard options.
//
// Some examples of this syntax are:
//
// +checkescape:all               - Analyzes for all escapes in this function and all calls.
// +checkescape:local             - Analyzes only for default local hard escapes.
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
package checkescape

import (
	"bufio"
	"bytes"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"io"
	"log"
	"path/filepath"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"
	"gvisor.dev/gvisor/tools/nogo/objdump"
)

const (
	// magic is the magic annotation.
	magic = "// +checkescape"

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
		return "stack: possible split on function entry"
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

// escapingBuiltins are builtins known to escape.
//
// These are lowered at an earlier stage of compilation to explicit function
// calls, but are not available for recursive analysis.
var escapingBuiltins = []string{
	"append",
	"makemap",
	"newobject",
	"mallocgc",
}

// packageEscapeFacts is the set of all functions in a package, and whether or
// not they recursively pass escape analysis.
//
// All the type names for receivers are encoded in the full key. The key
// represents the fully qualified package and type name used at link time.
//
// Note that each Escapes object is a summary. Local findings may be reported
// using more detailed information.
type packageEscapeFacts struct {
	Funcs map[string]Escapes
}

// AFact implements analysis.Fact.AFact.
func (*packageEscapeFacts) AFact() {}

// Analyzer includes specific results.
var Analyzer = &analysis.Analyzer{
	Name:      "checkescape",
	Doc:       "escape analysis checks based on +checkescape annotations",
	Run:       runSelectEscapes,
	Requires:  []*analysis.Analyzer{buildssa.Analyzer},
	FactTypes: []analysis.Fact{(*packageEscapeFacts)(nil)},
}

// EscapeAnalyzer includes all local escape results.
var EscapeAnalyzer = &analysis.Analyzer{
	Name:     "checkescape",
	Doc:      "complete local escape analysis results (requires Analyzer facts)",
	Run:      runAllEscapes,
	Requires: []*analysis.Analyzer{buildssa.Analyzer},
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
		pass.Reportf(es.CallSites[r][0].LocalPos, b.String())
	}
}

// MergeAll merges a sequence of escapes.
func MergeAll(others []Escapes) (es Escapes) {
	for _, other := range others {
		es.MergeWithCall(other, CallSite{})
	}
	return
}

// loadObjdump reads the objdump output.
//
// This records if there is a call any function for every source line. It is
// used only to remove false positives for escape analysis. The call will be
// elided if escape analysis is able to put the object on the heap exclusively.
//
// Note that the map uses <basename.go>:<line> because that is all that is
// provided in the objdump format. Since this is all local, it is sufficient.
func loadObjdump() (map[string][]string, error) {
	// Identify calls by address or name. Note that this is also
	// constructed dynamically below, as we encounted the addresses.
	// This is because some of the functions (duffzero) may have
	// jump targets in the middle of the function itself.
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
	addrsAllowed := make(map[string]struct{})

	// Build the map.
	nextFunc := "" // For funcsAllowed.
	m := make(map[string][]string)
	if err := objdump.Load(func(origR io.Reader) error {
		r := bufio.NewReader(origR)
	NextLine:
		for {
			line, err := r.ReadString('\n')
			if err != nil && err != io.EOF {
				return err
			}
			fields := strings.Fields(line)

			// Is this an "allowed" function definition?
			if len(fields) >= 2 && fields[0] == "TEXT" {
				nextFunc = strings.TrimSuffix(fields[1], "(SB)")
				if _, ok := funcsAllowed[nextFunc]; !ok {
					nextFunc = "" // Don't record addresses.
				}
			}
			if nextFunc != "" && len(fields) > 2 {
				// Save the given address (in hex form, as it appears).
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
			if len(fields) >= 5 && line[0] == ' ' {
				if !strings.Contains(fields[3], "CALL") {
					continue
				}
				site := fields[0]
				target := strings.TrimSuffix(fields[4], "(SB)")

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
					for name := range funcsAllowed {
						if strings.Contains(softTarget, name) {
							continue NextLine
						}
					}
				}

				// Does this exist already?
				existing, ok := m[site]
				if !ok {
					existing = make([]string, 0, 1)
				}
				for _, other := range existing {
					if target == other {
						continue NextLine
					}
				}
				existing = append(existing, target)
				m[site] = existing // Update.
			}
			if err == io.EOF {
				break
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}

	// Zap any accidental false positives.
	final := make(map[string][]string)
	for site, calls := range m {
		filteredCalls := make([]string, 0, len(calls))
		for _, call := range calls {
			if _, ok := addrsAllowed[call]; ok {
				continue // Omit this call.
			}
			filteredCalls = append(filteredCalls, call)
		}
		final[site] = filteredCalls
	}

	return final, nil
}

// poser is a type that implements Pos.
type poser interface {
	Pos() token.Pos
}

// runSelectEscapes runs with only select escapes.
func runSelectEscapes(pass *analysis.Pass) (interface{}, error) {
	return run(pass, false)
}

// runAllEscapes runs with all escapes included.
func runAllEscapes(pass *analysis.Pass) (interface{}, error) {
	return run(pass, true)
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
				if types[i] == "local" {
					// Limit search to local escapes.
					local = true
				} else if types[i] == "all" {
					// Append all reasons.
					reasons = append(reasons, allReasons...)
				} else if types[i] == "hard" {
					// Append all hard reasons.
					reasons = append(reasons, hardReasons...)
				} else {
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

// run performs the analysis.
func run(pass *analysis.Pass, localEscapes bool) (interface{}, error) {
	calls, callsErr := loadObjdump()
	if callsErr != nil {
		// Note that if this analysis fails, then we don't actually
		// fail the analyzer itself. We simply report every possible
		// escape. In most cases this will work just fine.
		log.Printf("WARNING: unable to load objdump: %v", callsErr)
	}
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
	callSite := func(inst ssa.Instruction) CallSite {
		return CallSite{
			LocalPos: inst.Pos(),
			Resolved: linePosition(inst, inst.Parent()),
		}
	}
	hasCall := func(inst poser) (string, bool) {
		p := linePosition(inst, nil)
		if callsErr != nil {
			// See above: we don't have access to the binary
			// itself, so need to include every possible call.
			return fmt.Sprintf("(possible, unable to load objdump: %v)", callsErr), true
		}
		s, ok := calls[p.Simplified()]
		if !ok {
			return "", false
		}
		// Join all calls together.
		return strings.Join(s, " or "), true
	}
	state := pass.ResultOf[buildssa.Analyzer].(*buildssa.SSA)

	// Build the exception list.
	exemptions := make(map[LinePosition]string)
	for _, f := range pass.Files {
		for _, cg := range f.Comments {
			for _, c := range cg.List {
				p := pass.Fset.Position(c.Slash)
				if strings.HasPrefix(strings.ToLower(c.Text), exempt) {
					exemptions[LinePosition{
						Filename: p.Filename,
						Line:     p.Line,
					}] = c.Text[len(exempt):]
				}
			}
		}
	}

	var loadFunc func(*ssa.Function) Escapes // Used below.
	analyzeInstruction := func(inst ssa.Instruction) (es Escapes) {
		cs := callSite(inst)
		if _, ok := exemptions[cs.Resolved]; ok {
			return // No escape.
		}
		switch x := inst.(type) {
		case *ssa.Call:
			if x.Call.IsInvoke() {
				// This is an interface dispatch. There is no
				// way to know if this is actually escaping or
				// not, since we don't know the underlying
				// type.
				call, _ := hasCall(inst)
				es.Add(interfaceInvoke, call, cs)
				return
			}
			switch x := x.Call.Value.(type) {
			case *ssa.Function:
				if x.Pkg == nil {
					// Can't resolve the package.
					es.Add(unknownPackage, "no package", cs)
					return
				}

				// Is this a local function? If yes, call the
				// function to load the local function. The
				// local escapes are the escapes found in the
				// local function.
				if x.Pkg.Pkg == pass.Pkg {
					es.MergeWithCall(loadFunc(x), cs)
					return
				}

				// If this package is the atomic package, the implementation
				// may be replaced by instrinsics that don't have analysis.
				if x.Pkg.Pkg.Path() == "sync/atomic" {
					return
				}

				// Recursively collect information.
				var imp packageEscapeFacts
				if !pass.ImportPackageFact(x.Pkg.Pkg, &imp) {
					// Unable to import the dependency; we must
					// declare these as escaping.
					es.Add(unknownPackage, "no analysis", cs)
					return
				}

				// The escapes of this instruction are the
				// escapes of the called function directly.
				// Note that this may record many escapes.
				es.MergeWithCall(imp.Funcs[x.RelString(x.Pkg.Pkg)], cs)
				return
			case *ssa.Builtin:
				// Ignore elided escapes.
				if _, has := hasCall(inst); !has {
					return
				}

				// Check if the builtin is escaping.
				for _, name := range escapingBuiltins {
					if x.Name() == name {
						es.Add(builtin, name, cs)
						return
					}
				}
			default:
				// All dynamic calls are counted as soft
				// escapes. They are similar to interface
				// dispatches. We cannot actually look up what
				// this refers to using static analysis alone.
				call, _ := hasCall(inst)
				es.Add(dynamicCall, call, cs)
			}
		case *ssa.Alloc:
			// Ignore non-heap allocations.
			if !x.Heap {
				return
			}

			// Ignore elided escapes.
			call, has := hasCall(inst)
			if !has {
				return
			}

			// This is a real heap allocation.
			es.Add(allocation, call, cs)
		case *ssa.MakeMap:
			es.Add(builtin, "makemap", cs)
		case *ssa.MakeSlice:
			es.Add(builtin, "makeslice", cs)
		case *ssa.MakeClosure:
			es.Add(builtin, "makeclosure", cs)
		case *ssa.MakeChan:
			es.Add(builtin, "makechan", cs)
		}
		return
	}

	var analyzeBasicBlock func(*ssa.BasicBlock) []Escapes // Recursive.
	analyzeBasicBlock = func(block *ssa.BasicBlock) (rval []Escapes) {
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

		// Check for a stack split.
		if call, has := hasCall(fn); has {
			var ss Escapes
			ss.Add(stackSplit, call, CallSite{
				LocalPos: fn.Pos(),
				Resolved: linePosition(fn, fn.Parent()),
			})
			es = append(es, ss)
		}

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
		loadFunc(fn)
	}

	if !localEscapes {
		// Export all findings for future packages. We only do this in
		// non-local escapes mode, and expect to run this analysis
		// after the SelectAnalysis.
		pass.ExportPackageFact(&packageEscapeFacts{
			Funcs: mergedEscapes,
		})
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
			var (
				reasons     []EscapeReason
				local       bool
				testReasons map[EscapeReason]bool
			)
			if localEscapes {
				// Find all hard escapes.
				reasons = hardReasons
			} else {
				// Find all declared reasons.
				reasons, local, testReasons = findReasons(pass, fdecl)
			}

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
				pass.Reportf(fdecl.Pos(), fmt.Sprintf("testescapes not found: reason=%s, local=%t", reason, local))
			}
			if len(testReasons) > 0 {
				// Report for debugging.
				merged.Reportf(pass)
			}
		}
	}

	return nil, nil
}
