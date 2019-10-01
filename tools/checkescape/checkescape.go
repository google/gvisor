// Copyright 2019 The gVisor Authors.
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
// 	interface: A call is made via an interface whicy *may* escape (soft).
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
// Note that all of the above can be inverted by using +testescape. The
// +checkescape keyword will ensure failure if the class of escape occurs,
// whereas +testescape will fail if the given class of escape does not occur.
//
// Local exemptions can be made by a comment of the form "// escapes: reason."
// This must appear on the line of the escape and will also apply to callers of
// the function as well (for non-local escape analysis).
//
package checkescape

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"
)

const (
	// magic is the magic annotation.
	magic = "// +checkescape"

	// magicParams is the magic annotation with specific parameters.
	magicParams = magic + ":"

	// testMagic is the test magic annotation (parameters required).
	testMagic = "// +testescape:"

	// exempt is the exemption annotation.
	exempt = "// escapes:"
)

// escapingBuiltins are builtins known to escape.
//
// These are lowered at an earlier stage of compilation to explicit function
// calls, but are not available for recursive analysis.
var escapingBuiltins = []string{
	"append",
	"makemap",
}

// Analyzer defines the entrypoint.
var Analyzer = &analysis.Analyzer{
	Name: "checkescape",
	Doc:  "surfaces recursive escape analysis results",
	Requires: []*analysis.Analyzer{
		buildssa.Analyzer,
	},
	Run: run,
}

// packageEscapeFacts is the set of all functions in a package, and whether or
// not they recursively pass escape analysis.
//
// All the type names for receivers are encoded in the full key. The key
// represents the fully qualified package and type name used at link time.
type packageEscapeFacts struct {
	Funcs map[string][]Escape
}

// AFact implements analysis.Fact.AFact.
func (*packageEscapeFacts) AFact() {}

// CallSite is a single call site.
//
// These can be chained.
type CallSite struct {
	LocalPos token.Pos
	Resolved LinePosition
}

// Escape is a single escape instance.
type Escape struct {
	Reason EscapeReason
	Detail string
	Chain  []CallSite
}

// LinePosition is a low-resolution token.Position.
//
// This is used to match against possible exemptions placed in the source.
type LinePosition struct {
	Filename string
	Line     int
}

// String implements fmt.Stringer.String.
//
// Note that this string will contain new lines.
func (e *Escape) String() string {
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s (%s)", e.Reason.String(), e.Detail)
	for i, cs := range e.Chain {
		if i == len(e.Chain)-1 {
			fmt.Fprintf(&b, "\n @ ")
		} else {
			fmt.Fprintf(&b, "\n + ")
		}
		fmt.Fprintf(&b, " %s:%d", cs.Resolved.Filename, cs.Resolved.Line)
	}
	return b.String()
}

// EscapeReason is an escape reason.
//
// This is a simple enum.
type EscapeReason int

const (
	interfaceInvoke EscapeReason = iota
	unknownPackage
	allocation
	builtin
	dynamicCall
)

// String returns the string for the EscapeReason.
//
// Note that this also implicitly defines the reverse string -> EscapeReason
// mapping, which is the word before the colon (computed below).
func (e EscapeReason) String() string {
	switch e {
	case interfaceInvoke:
		return "interface: function invocation via interface"
	case unknownPackage:
		return "unknown: no package information available"
	case allocation:
		return "heap: call to runtime heap allocation"
	case builtin:
		return "builtin: call to runtime builtin"
	case dynamicCall:
		return "dynamic: call via dynamic function"
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

// run performs the analysis.
func run(pass *analysis.Pass) (interface{}, error) {
	pef := packageEscapeFacts{
		Funcs: make(map[string][]Escape),
	}
	callSite := func(inst ssa.Instruction) CallSite {
		pos := inst.Pos()
		p := pass.Fset.Position(inst.Pos())
		if p.Filename == "" || p.Line == 0 {
			pos = inst.Parent().Pos()
			p = pass.Fset.Position(pos)
		}
		return CallSite{
			LocalPos: pos,
			Resolved: LinePosition{
				Filename: p.Filename,
				Line:     p.Line,
			},
		}
	}
	escapes := func(reason EscapeReason, detail string, inst ssa.Instruction) []Escape {
		es := Escape{
			Reason: reason,
			Detail: detail,
			Chain:  []CallSite{callSite(inst)},
		}
		return []Escape{es}
	}
	resolve := func(sub []Escape, inst ssa.Instruction) (es []Escape) {
		for _, e := range sub {
			es = append(es, Escape{
				Reason: e.Reason,
				Detail: e.Detail,
				Chain:  append([]CallSite{callSite(inst)}, e.Chain...),
			})
		}
		return es
	}
	state := pass.ResultOf[buildssa.Analyzer].(*buildssa.SSA)

	var loadFunc func(*ssa.Function) []Escape // Used below.

	analyzeInstruction := func(inst ssa.Instruction) []Escape {
		if call, ok := inst.(*ssa.Call); ok && call.Call.IsInvoke() {
			// This is an interface dispatch.
			return escapes(interfaceInvoke, "call", inst)
		} else if ok {
			switch x := call.Call.Value.(type) {
			case *ssa.Function:
				if x.Pkg == nil {
					// Can't resolve the package.
					return escapes(unknownPackage, "no package", inst)
				}

				// Is this a local function? If yes, call the
				// function to load the local function. The
				// local escapes are the escapes found in the
				// local function.
				if x.Pkg.Pkg == pass.Pkg {
					return resolve(loadFunc(x), inst)
				}

				// Recursively collect information from
				// the other analyzers.
				var imp packageEscapeFacts
				if !pass.ImportPackageFact(x.Pkg.Pkg, &imp) {
					// Is the package the sync or
					// sync/atomic packages? We allow those
					// but treat all other packages are
					// "unknown". There is no analysis
					// available for the standard library.
					if x.Pkg.Pkg.Name() == "atomic" || x.Pkg.Pkg.Name() == "sync" {
						return nil // No escapes.
					}
					// Unable to import the dependency; we must
					// declare these as escaping.
					return escapes(unknownPackage, "no analysis", inst)
				}
				// The escapes of this instruction are the
				// escapes of the called function directly.
				return resolve(imp.Funcs[x.RelString(x.Pkg.Pkg)], inst)
			case *ssa.Builtin:
				// Check if the builtin is escaping.
				for _, name := range escapingBuiltins {
					if x.Name() == name {
						return escapes(builtin, name, inst)
					}
				}
			default:
				// All dynamic calls are counted as soft
				// escapes. They are similar to interface
				// dispatches.
				return escapes(dynamicCall, "dynamic call", inst)
			}
		} else if alloc, ok := inst.(*ssa.Alloc); ok && alloc.Heap {
			// This is a heap allocation.
			return escapes(allocation, "heap allocation", inst)
		} else {
			// Grab additional types.
			switch inst.(type) {
			case *ssa.MakeMap:
				return escapes(builtin, "makemap", inst)
			case *ssa.MakeSlice:
				return escapes(builtin, "makeslice", inst)
			case *ssa.MakeClosure:
				return escapes(builtin, "makeclosure", inst)
			case *ssa.MakeChan:
				return escapes(builtin, "makechan", inst)
			}
		}
		return nil // No escapes.
	}

	var analyzeBasicBlock func(*ssa.BasicBlock) []Escape // Recursive.
	analyzeBasicBlock = func(block *ssa.BasicBlock) (rval []Escape) {
		for _, inst := range block.Instrs {
			rval = append(rval, analyzeInstruction(inst)...)
		}
		return rval // N.B. may be empty.
	}

	loadFunc = func(fn *ssa.Function) []Escape {
		// Is this already available?
		name := fn.RelString(pass.Pkg)
		if es, ok := pef.Funcs[name]; ok {
			return es
		}

		// In the case of a true cycle, we assume that the current
		// function itself has no escapes until the rest of the
		// analysis is complete. This will trip the above in the case
		// of a cycle of any kind.
		pef.Funcs[name] = nil

		// Perform the basic analysis.
		var es []Escape
		if fn.Recover != nil {
			es = append(es, analyzeBasicBlock(fn.Recover)...)
		}
		for _, block := range fn.Blocks {
			es = append(es, analyzeBasicBlock(block)...)
		}

		// Save the result and return.
		pef.Funcs[name] = es
		return es
	}

	// Complete all local functions.
	for _, fn := range state.SrcFuncs {
		loadFunc(fn)
	}

	// Build the exception list.
	exceptions := make(map[LinePosition]string)
	for _, f := range pass.Files {
		for _, cg := range f.Comments {
			for _, c := range cg.List {
				p := pass.Fset.Position(c.Slash)
				if strings.HasPrefix(c.Text, exempt) {
					exceptions[LinePosition{
						Filename: p.Filename,
						Line:     p.Line,
					}] = c.Text[len(exempt):]
				}
			}
		}
	}

	// Delete everything matching the exceptions.
	//
	// This has the implication that exceptions are applied recursively,
	// since this now modified set is what will be saved.
	for name, escapes := range pef.Funcs {
		var newEscapes []Escape
		for _, escape := range escapes {
			// Check all exceptions.
			isException := false
			for line, _ := range exceptions {
				if escape.Chain[0].Resolved == line {
					isException = true
					break
				}
			}
			if !isException {
				// Record this escape; not an exception.
				newEscapes = append(newEscapes, escape)
			}
		}
		pef.Funcs[name] = newEscapes // Update.
	}

	// Export all findings for future packages.
	pass.ExportPackageFact(&pef)

	// Scan all functions for violations.
	for _, f := range pass.Files {
		// Scan all declarations.
		for _, decl := range f.Decls {
			fdecl, ok := decl.(*ast.FuncDecl)
			// Function declaration?
			if !ok {
				continue
			}
			// Is there a comment?
			if fdecl.Doc == nil {
				continue
			}
			var (
				reasons     []EscapeReason
				found       bool
				local       bool
				testReasons = make(map[EscapeReason]bool) // reason -> local?
			)
			// Does the comment contain a +checkescape line?
			for _, c := range fdecl.Doc.List {
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
				continue
			}

			// Scan for matches.
			fn := pass.TypesInfo.Defs[fdecl.Name].(*types.Func)
			name := state.Pkg.Prog.FuncValue(fn).RelString(pass.Pkg)
			es, ok := pef.Funcs[name]
			if !ok {
				pass.Reportf(fdecl.Pos(), "internal error: function %s not found.", name)
				continue
			}
			for _, e := range es {
				for _, r := range reasons {
					// Is does meet our local requirement?
					if local && len(e.Chain) > 1 {
						continue
					}
					// Does this match the reason? Emit
					// with a full stack trace that
					// explains why this violates our
					// constraints.
					if e.Reason == r {
						pass.Reportf(e.Chain[0].LocalPos, "%s", e.String())
					}
				}
			}

			// Scan for test (required) matches.
			testReasonsFound := make(map[EscapeReason]bool)
			for _, e := range es {
				// Is this local?
				local, ok := testReasons[e.Reason]
				wantLocal := len(e.Chain) == 1
				testReasonsFound[e.Reason] = wantLocal
				if !ok {
					continue
				}
				if local == wantLocal {
					delete(testReasons, e.Reason)
				}
			}
			for reason, local := range testReasons {
				// We didn't find the escapes we wanted.
				pass.Reportf(fdecl.Pos(), fmt.Sprintf("testescapes not found: reason=%s, local=%t", reason, local))
			}
			if len(testReasons) > 0 {
				// Dump all reasons found to help in debugging.
				for reason, local := range testReasonsFound {
					pass.Reportf(fdecl.Pos(), fmt.Sprintf("testescapes found: reason=%s, local=%t", reason, local))
				}
			}
		}
	}

	return nil, nil
}

func init() {
	gob.Register(&packageEscapeFacts{})
}
