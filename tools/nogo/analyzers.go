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

package nogo

import (
	"encoding/gob"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/asmdecl"
	"golang.org/x/tools/go/analysis/passes/assign"
	"golang.org/x/tools/go/analysis/passes/atomic"
	"golang.org/x/tools/go/analysis/passes/bools"
	"golang.org/x/tools/go/analysis/passes/buildtag"
	"golang.org/x/tools/go/analysis/passes/cgocall"
	"golang.org/x/tools/go/analysis/passes/composite"
	"golang.org/x/tools/go/analysis/passes/copylock"
	"golang.org/x/tools/go/analysis/passes/errorsas"
	"golang.org/x/tools/go/analysis/passes/httpresponse"
	"golang.org/x/tools/go/analysis/passes/loopclosure"
	"golang.org/x/tools/go/analysis/passes/lostcancel"
	"golang.org/x/tools/go/analysis/passes/nilfunc"
	"golang.org/x/tools/go/analysis/passes/nilness"
	"golang.org/x/tools/go/analysis/passes/printf"
	"golang.org/x/tools/go/analysis/passes/shadow"
	"golang.org/x/tools/go/analysis/passes/shift"
	"golang.org/x/tools/go/analysis/passes/stdmethods"
	"golang.org/x/tools/go/analysis/passes/stringintconv"
	"golang.org/x/tools/go/analysis/passes/structtag"
	"golang.org/x/tools/go/analysis/passes/tests"
	"golang.org/x/tools/go/analysis/passes/unmarshal"
	"golang.org/x/tools/go/analysis/passes/unreachable"
	"golang.org/x/tools/go/analysis/passes/unsafeptr"
	"golang.org/x/tools/go/analysis/passes/unusedresult"
	"honnef.co/go/tools/staticcheck"
	"honnef.co/go/tools/stylecheck"

	"gvisor.dev/gvisor/tools/checkatomic"
	"gvisor.dev/gvisor/tools/checkescape"
	"gvisor.dev/gvisor/tools/checklocks"
	"gvisor.dev/gvisor/tools/checkunsafe"
)

// AllAnalyzers is a list of all available analyzers.
var AllAnalyzers = []*analysis.Analyzer{
	asmdecl.Analyzer,
	assign.Analyzer,
	atomic.Analyzer,
	bools.Analyzer,
	buildtag.Analyzer,
	cgocall.Analyzer,
	composite.Analyzer,
	copylock.Analyzer,
	errorsas.Analyzer,
	httpresponse.Analyzer,
	loopclosure.Analyzer,
	lostcancel.Analyzer,
	nilfunc.Analyzer,
	nilness.Analyzer,
	printf.Analyzer,
	shift.Analyzer,
	stdmethods.Analyzer,
	stringintconv.Analyzer,
	shadow.Analyzer,
	structtag.Analyzer,
	tests.Analyzer,
	unmarshal.Analyzer,
	unreachable.Analyzer,
	unsafeptr.Analyzer,
	unusedresult.Analyzer,
	checkatomic.Analyzer,
	checkescape.Analyzer,
	checkunsafe.Analyzer,
	checklocks.Analyzer,
}

// EscapeAnalyzers is a list of escape-related analyzers.
var EscapeAnalyzers = []*analysis.Analyzer{
	checkescape.EscapeAnalyzer,
}

func register(all []*analysis.Analyzer) {
	// Register all fact types.
	//
	// N.B. This needs to be done recursively, because there may be
	// analyzers in the Requires list that do not appear explicitly above.
	registered := make(map[*analysis.Analyzer]struct{})
	var registerOne func(*analysis.Analyzer)
	registerOne = func(a *analysis.Analyzer) {
		if _, ok := registered[a]; ok {
			return
		}

		// Register dependencies.
		for _, da := range a.Requires {
			registerOne(da)
		}

		// Register local facts.
		for _, f := range a.FactTypes {
			gob.Register(f)
		}

		registered[a] = struct{}{} // Done.
	}
	for _, a := range all {
		registerOne(a)
	}
}

func init() {
	// Add all staticcheck analyzers.
	for _, a := range staticcheck.Analyzers {
		AllAnalyzers = append(AllAnalyzers, a)
	}
	// Add all stylecheck analyzers.
	for _, a := range stylecheck.Analyzers {
		AllAnalyzers = append(AllAnalyzers, a)
	}

	// Register lists.
	register(AllAnalyzers)
	register(EscapeAnalyzers)
}
