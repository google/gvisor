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
	"strings"

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

	"gvisor.dev/gvisor/tools/checkaligned"
	"gvisor.dev/gvisor/tools/checkescape"
	"gvisor.dev/gvisor/tools/checkinfo"
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

	// allFactTypes is a list of all fact types, useful as a filter.
	allFactTypes = make(map[reflect.Type]bool)

	// allFactNames is a list with all fact names.
	allFactNames = make(map[reflect.Type]string)
)

// findAnalyzer maps orig to an analyzer instance.
//
// This is guaranteed to work provided allAnalyzers is made into a transitive
// closure of all known analyzers (see init).
func findAnalyzer(orig *analysis.Analyzer) analyzer {
	return allAnalyzers[orig]
}

// registerFactType registers a analysis.Fact.
func registerFactType(f analysis.Fact) {
	// Already registered?
	t := reflect.TypeOf(f)
	if _, ok := allFactTypes[t]; ok {
		return
	}

	// Register the type.
	gob.Register(f)
	allFactTypes[t] = true
	s := t.String()
	for len(s) > 0 && s[0] == '*' {
		s = s[1:]
	}

	// Take only the final element.
	parts := strings.Split(s, ".")
	allFactNames[t] = parts[len(parts)-1]
}

// register recurisvely registers an analyzer.
func register(a analyzer) {
	// Already registered?
	if _, ok := allAnalyzers[a.Legacy()]; ok {
		return
	}

	// Register all fact types.
	for _, f := range a.Legacy().FactTypes {
		registerFactType(f)
	}

	// Register dependencies.
	for _, orig := range a.Legacy().Requires {
		if findAnalyzer(orig) == nil {
			register(&plainAnalyzer{orig})
		}
	}

	// Save the analyzer.
	allAnalyzers[a.Legacy()] = a
}

func init() {
	// Standard & internal analyzers.
	register(&plainAnalyzer{asmdecl.Analyzer})
	register(&plainAnalyzer{assign.Analyzer})
	register(&plainAnalyzer{atomic.Analyzer})
	register(&plainAnalyzer{bools.Analyzer})
	register(&plainAnalyzer{buildtag.Analyzer})
	register(&plainAnalyzer{cgocall.Analyzer})
	register(&plainAnalyzer{composite.Analyzer})
	register(&plainAnalyzer{copylock.Analyzer})
	register(&plainAnalyzer{errorsas.Analyzer})
	register(&plainAnalyzer{httpresponse.Analyzer})
	register(&plainAnalyzer{loopclosure.Analyzer})
	register(&plainAnalyzer{lostcancel.Analyzer})
	register(&plainAnalyzer{nilfunc.Analyzer})
	register(&plainAnalyzer{nilness.Analyzer})
	register(&plainAnalyzer{printf.Analyzer})
	register(&plainAnalyzer{shift.Analyzer})
	register(&plainAnalyzer{stdmethods.Analyzer})
	register(&plainAnalyzer{stringintconv.Analyzer})
	register(&plainAnalyzer{shadow.Analyzer})
	register(&plainAnalyzer{structtag.Analyzer})
	register(&plainAnalyzer{tests.Analyzer})
	register(&plainAnalyzer{unmarshal.Analyzer})
	register(&plainAnalyzer{unreachable.Analyzer})
	register(&plainAnalyzer{unsafeptr.Analyzer})
	register(&plainAnalyzer{unusedresult.Analyzer})
	register(checkescape.Analyzer)
	register(&plainAnalyzer{checkinfo.Analyzer})
	register(&plainAnalyzer{checkunsafe.Analyzer})
	register(&plainAnalyzer{checklinkname.Analyzer})
	register(&plainAnalyzer{checklocks.Analyzer})
	register(&plainAnalyzer{checkaligned.Analyzer})

	// Add all staticcheck analyzers.
	for _, a := range staticcheck.Analyzers {
		register(&plainAnalyzer{a.Analyzer})
	}

	// Add all stylecheck analyzers.
	for _, a := range stylecheck.Analyzers {
		register(&plainAnalyzer{a.Analyzer})
	}
}
