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

// Package deferunlock checks that locks always have a corresponding defer.
package deferunlock

import (
	"fmt"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"
)

// Analyzer defines the entrypoint.
var Analyzer = &analysis.Analyzer{
	Name:     "deferunlock",
	Doc:      "checks that locks have a corresponding defer unlock",
	Run:      run,
	Requires: []*analysis.Analyzer{buildssa.Analyzer},
}

const (
	syncPackage = "gvisor.dev/gvisor/pkg/sync"
	exemptMagic = "nodefer:"
)

var pairs = map[string]string{
	"(*" + syncPackage + ".Mutex).Lock":    "(*" + syncPackage + ".Mutex).Unlock",
	"(*" + syncPackage + ".RWMutex).Lock":  "(*" + syncPackage + ".RWMutex).Unlock",
	"(*" + syncPackage + ".RWMutex).RLock": "(*" + syncPackage + ".RWMutex).RUnlock",
}

type exceptionEntry struct {
	filename string
	line     int
}

type hasReferrers interface {
	fmt.Stringer
	Referrers() *[]ssa.Instruction
}

func isDefer(inst ssa.Instruction, fullName string) (string, bool) {
	// Is this the defer call itself?
	if deferCall, ok := inst.(*ssa.Defer); ok {
		if deferCall.Call.IsInvoke() {
			return deferCall.Call.String(), false
		}
		deferredFn, ok := deferCall.Call.Value.(*ssa.Function)
		if !ok {
			return deferCall.Call.String(), false
		}
		deferFullName := deferredFn.RelString(nil)
		return deferFullName, fullName == deferFullName
	}

	// Allow the address to be taken for dispatch. This is the
	// common case, e.g. you have &x.mu below:
	//	x.mu.Lock()
	//	defer x.mu.Unlock()
	value, ok := inst.(ssa.Value)
	if !ok {
		return inst.String(), false
	}
	refs := value.Referrers()
	if refs == nil {
		return inst.String() + " (no referrers)", false
	}
	for _, ref := range *refs {
		if got, ok := isDefer(ref, fullName); ok {
			return got, ok
		}
	}

	// Include the referrs.
	return fmt.Sprintf("%s (referrers: %+v)", inst.String(), *refs), false
}

func run(pass *analysis.Pass) (interface{}, error) {
	// Build all exceptions, by line number.
	exceptions := make(map[exceptionEntry]bool)
	for _, f := range pass.Files {
		for _, comment := range f.Comments {
			for _, c := range comment.List {
				// Does the comment contain a nodefer: explanation?
				if strings.Contains(c.Text, exemptMagic) {
					p := pass.Fset.Position(c.Slash)
					exceptions[exceptionEntry{
						filename: p.Filename,
						line:     p.Line,
					}] = true
				}
			}
		}
	}

	// Scan all functions.
	funcs := pass.ResultOf[buildssa.Analyzer].(*buildssa.SSA).SrcFuncs
	for _, f := range funcs {
		// Scan all code.
		for _, b := range f.Blocks {
			for i := 0; i < len(b.Instrs); i++ {
				// Is this a relevant call?
				call, ok := b.Instrs[i].(*ssa.Call)
				if !ok {
					continue
				}
				if call.Call.IsInvoke() {
					continue
				}
				calledFn, ok := call.Call.Value.(*ssa.Function)
				if !ok {
					continue
				}
				fullName := calledFn.RelString(nil)
				neededDeferName, ok := pairs[fullName]
				if !ok {
					continue
				}

				// Skip?
				p := pass.Fset.Position(b.Instrs[i].Pos())
				foundException := exceptions[exceptionEntry{
					filename: p.Filename,
					line:     p.Line,
				}]
				if foundException {
					continue
				}

				// Find the defer.
				if i >= len(b.Instrs)-1 {
					pass.Reportf(b.Instrs[i].Pos(), "lock statement %s is last instruction in a block", fullName)
					continue
				}
				if got, ok := isDefer(b.Instrs[i+1], neededDeferName); !ok {
					pass.Reportf(b.Instrs[i].Pos(), "expected defer %s following %s, got %s",
						neededDeferName, fullName, got)
					continue
				}
			}
		}
	}
	return nil, nil
}
