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

package check

import (
	"encoding/gob"
	"io"
	"reflect"

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
	"honnef.co/go/tools/analysis/lint"
	"honnef.co/go/tools/quickfix"
	"honnef.co/go/tools/simple"
	"honnef.co/go/tools/staticcheck"
	"honnef.co/go/tools/stylecheck"
	"honnef.co/go/tools/unused"

	"gvisor.dev/gvisor/tools/checkaligned"
	"gvisor.dev/gvisor/tools/checkconst"
	"gvisor.dev/gvisor/tools/checkescape"
	"gvisor.dev/gvisor/tools/checklinkname"
	"gvisor.dev/gvisor/tools/checklocks"
	"gvisor.dev/gvisor/tools/checkunsafe"
)

// binaryAnalyzer is a special class of analyzer which supports an additional
// operation to run an analyzer with the object binary data.
type binaryAnalyzer interface {
	// Run runs the analyzer with the given binary data.
	Run(*analysis.Pass, io.Reader) (any, error)
}

// analyzer is a simple analysis.Analyzer interface.
//
// This is implemented by plainAnalyzer, and is used to allow calls to
// non-standard analyzers (e.g. checkescape, which requires the objdump output
// in addition to the existing pass information).
type analyzer interface {
	Legacy() *analysis.Analyzer
}

// plainAnalyzer implements analyzer.
type plainAnalyzer struct {
	*analysis.Analyzer
}

// Legacy implements analyzer.Legacy.
func (pa *plainAnalyzer) Legacy() *analysis.Analyzer {
	return pa.Analyzer
}

var (
	// allAnalyzers is a list of all available analyzers.
	//
	// This is guaranteed to be complete closure around the dependency
	// graph of all analyzers (via the "Requires" attribute, below).
	// Therefore, to map an *analysis.Analyzer to a runner, you may safely
	// use "findAnalyzer".
	allAnalyzers = make(map[*analysis.Analyzer]analyzer)

	// renderAnalyzers is a list of analyzers used during template render.
	renderAnalyzers = make(map[*analysis.Analyzer]analyzer)

	// allFactTypes is a list of all fact types, useful as a filter.
	allFactTypes = make(map[reflect.Type]bool)
)

// findAnalyzer maps orig to an analyzer instance.
//
// This is guaranteed to work provided allAnalyzers is made into a transitive
// closure of all known analyzers (see init).
func findAnalyzer(analyzerSet map[*analysis.Analyzer]analyzer, orig *analysis.Analyzer) analyzer {
	return analyzerSet[orig]
}

// registerFactType registers an analysis.Fact.
func registerFactType(f analysis.Fact) {
	// Already registered?
	t := reflect.TypeOf(f)
	if _, ok := allFactTypes[t]; ok {
		return
	}

	// Register the type.
	gob.Register(f)
	allFactTypes[t] = true
}

// register recursively registers an analyzer.
func register(analyzerSet map[*analysis.Analyzer]analyzer, a analyzer) {
	// Already registered?
	if _, ok := analyzerSet[a.Legacy()]; ok {
		return
	}

	// Register all fact types.
	for _, f := range a.Legacy().FactTypes {
		registerFactType(f)
	}

	// Register dependencies.
	for _, orig := range a.Legacy().Requires {
		if findAnalyzer(analyzerSet, orig) == nil {
			register(analyzerSet, &plainAnalyzer{orig})
		}
	}

	// Save the analyzer.
	analyzerSet[a.Legacy()] = a
}

func init() {
	// Standard & internal analyzers.
	register(allAnalyzers, &plainAnalyzer{asmdecl.Analyzer})
	register(allAnalyzers, &plainAnalyzer{assign.Analyzer})
	register(allAnalyzers, &plainAnalyzer{atomic.Analyzer})
	register(allAnalyzers, &plainAnalyzer{bools.Analyzer})
	register(allAnalyzers, &plainAnalyzer{buildtag.Analyzer})
	register(allAnalyzers, &plainAnalyzer{cgocall.Analyzer})
	register(allAnalyzers, &plainAnalyzer{composite.Analyzer})
	register(allAnalyzers, &plainAnalyzer{copylock.Analyzer})
	register(allAnalyzers, &plainAnalyzer{errorsas.Analyzer})
	register(allAnalyzers, &plainAnalyzer{httpresponse.Analyzer})
	register(allAnalyzers, &plainAnalyzer{loopclosure.Analyzer})
	register(allAnalyzers, &plainAnalyzer{lostcancel.Analyzer})
	register(allAnalyzers, &plainAnalyzer{nilfunc.Analyzer})
	register(allAnalyzers, &plainAnalyzer{nilness.Analyzer})
	register(allAnalyzers, &plainAnalyzer{printf.Analyzer})
	register(allAnalyzers, &plainAnalyzer{shift.Analyzer})
	register(allAnalyzers, &plainAnalyzer{stdmethods.Analyzer})
	register(allAnalyzers, &plainAnalyzer{stringintconv.Analyzer})
	register(allAnalyzers, &plainAnalyzer{shadow.Analyzer})
	register(allAnalyzers, &plainAnalyzer{structtag.Analyzer})
	register(allAnalyzers, &plainAnalyzer{tests.Analyzer})
	register(allAnalyzers, &plainAnalyzer{unmarshal.Analyzer})
	register(allAnalyzers, &plainAnalyzer{unreachable.Analyzer})
	register(allAnalyzers, &plainAnalyzer{unsafeptr.Analyzer})
	register(allAnalyzers, &plainAnalyzer{unusedresult.Analyzer})
	register(allAnalyzers, checkescape.Analyzer)
	register(allAnalyzers, &plainAnalyzer{checkconst.Analyzer})
	register(allAnalyzers, &plainAnalyzer{checkunsafe.Analyzer})
	register(allAnalyzers, &plainAnalyzer{checklinkname.Analyzer})
	register(allAnalyzers, &plainAnalyzer{checklocks.Analyzer})
	register(allAnalyzers, &plainAnalyzer{checkaligned.Analyzer})

	for _, analyzers := range [][]*lint.Analyzer{
		quickfix.Analyzers,
		simple.Analyzers,
		staticcheck.Analyzers,
		stylecheck.Analyzers,
		{unused.Analyzer},
	} {
		for _, a := range analyzers {
			register(allAnalyzers, &plainAnalyzer{a.Analyzer})
		}
	}

	// Template rendering does not require all analyzers.
	register(renderAnalyzers, &plainAnalyzer{checkconst.Analyzer})
	for _, a := range staticcheck.Analyzers {
		register(renderAnalyzers, &plainAnalyzer{a.Analyzer})
	}
}
