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

	"gvisor.dev/gvisor/tools/checkescape"
	"gvisor.dev/gvisor/tools/checkunsafe"
)

var analyzerConfig = map[*analysis.Analyzer]matcher{
	// Standard analyzers.
	asmdecl.Analyzer: alwaysMatches(),
	assign.Analyzer: externalExcluded(
		".*gazelle/walk/walk.go", // False positive.
	),
	atomic.Analyzer:   alwaysMatches(),
	bools.Analyzer:    alwaysMatches(),
	buildtag.Analyzer: alwaysMatches(),
	cgocall.Analyzer:  alwaysMatches(),
	composite.Analyzer: and(
		disableMatches(), // Disabled for now.
		resultExcluded{
			"Object_",
			"Range{",
		},
	),
	copylock.Analyzer:     internalMatches(), // Common external issues (e.g. protos).
	errorsas.Analyzer:     alwaysMatches(),
	httpresponse.Analyzer: alwaysMatches(),
	loopclosure.Analyzer:  alwaysMatches(),
	lostcancel.Analyzer:   internalMatches(), // Common external issues.
	nilfunc.Analyzer:      alwaysMatches(),
	nilness.Analyzer: and(
		internalMatches(), // Common "tautological checks".
		internalExcluded(
			"pkg/sentry/platform/kvm/kvm_test.go", // Intentional.
			"tools/bigquery/bigquery.go",          // False positive.
		),
	),
	printf.Analyzer:     alwaysMatches(),
	shift.Analyzer:      alwaysMatches(),
	stdmethods.Analyzer: internalMatches(), // Common external issues (e.g. methods named "Write").
	stringintconv.Analyzer: and(
		internalExcluded(),
		externalExcluded(
			".*protobuf/.*.go",              // Bad conversions.
			".*flate/huffman_bit_writer.go", // Bad conversion.
		),
	),
	shadow.Analyzer:      disableMatches(),  // Disabled for now.
	structtag.Analyzer:   internalMatches(), // External not subject to rules.
	tests.Analyzer:       alwaysMatches(),
	unmarshal.Analyzer:   alwaysMatches(),
	unreachable.Analyzer: internalMatches(),
	unsafeptr.Analyzer: and(
		internalMatches(),
		internalExcluded(
			".*_test.go",                                               // Exclude tests.
			"pkg/flipcall/.*_unsafe.go",                                // Special case.
			"pkg/gohacks/gohacks_unsafe.go",                            // Special case.
			"pkg/sentry/fs/fsutil/host_file_mapper_unsafe.go",          // Special case.
			"pkg/sentry/platform/kvm/bluepill_unsafe.go",               // Special case.
			"pkg/sentry/platform/kvm/machine_unsafe.go",                // Special case.
			"pkg/sentry/platform/ring0/pagetables/allocator_unsafe.go", // Special case.
			"pkg/sentry/platform/safecopy/safecopy_unsafe.go",          // Special case.
			"pkg/sentry/vfs/mount_unsafe.go",                           // Special case.
			"pkg/sentry/platform/systrap/stub_unsafe.go",               // Special case.
			"pkg/sentry/platform/systrap/switchto_google_unsafe.go",    // Special case.
			"pkg/sentry/platform/systrap/sysmsg_thread_unsafe.go",      // Special case.
		),
	),
	unusedresult.Analyzer: alwaysMatches(),

	// Internal analyzers: external packages not subject.
	checkescape.Analyzer: internalMatches(),
	checkunsafe.Analyzer: internalMatches(),
}
