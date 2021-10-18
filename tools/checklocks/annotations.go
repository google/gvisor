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

package checklocks

import (
	"fmt"

	"go/token"
	"strconv"
	"strings"
)

const (
	checkLocksAnnotation     = "// +checklocks:"
	checkLocksAnnotationRead = "// +checklocksread:"
	checkLocksAcquires       = "// +checklocksacquire:"
	checkLocksAcquiresRead   = "// +checklocksacquireread:"
	checkLocksReleases       = "// +checklocksrelease:"
	checkLocksReleasesRead   = "// +checklocksreleaseread:"
	checkLocksIgnore         = "// +checklocksignore"
	checkLocksForce          = "// +checklocksforce"
	checkLocksFail           = "// +checklocksfail"
	checkAtomicAnnotation    = "// +checkatomic"
)

// failData indicates an expected failure.
type failData struct {
	pos   token.Pos
	count int
	seen  int
}

// positionKey is a simple position string.
type positionKey string

// positionKey converts from a token.Pos to a key we can use to track failures
// as the position of the failure annotation is not the same as the position of
// the actual failure (different column/offsets). Hence we ignore these fields
// and only use the file/line numbers to track failures.
func (pc *passContext) positionKey(pos token.Pos) positionKey {
	position := pc.pass.Fset.Position(pos)
	return positionKey(fmt.Sprintf("%s:%d", position.Filename, position.Line))
}

// addFailures adds an expected failure.
func (pc *passContext) addFailures(pos token.Pos, s string) {
	count := 1
	if len(s) > 0 && s[0] == ':' {
		parsedCount, err := strconv.Atoi(s[1:])
		if err != nil {
			pc.pass.Reportf(pos, "unable to parse failure annotation %q: %v", s[1:], err)
			return
		}
		count = parsedCount
	}
	pc.failures[pc.positionKey(pos)] = &failData{
		pos:   pos,
		count: count,
	}
}

// addExemption adds an exemption.
func (pc *passContext) addExemption(pos token.Pos) {
	pc.exemptions[pc.positionKey(pos)] = struct{}{}
}

// addForce adds a force annotation.
func (pc *passContext) addForce(pos token.Pos) {
	pc.forced[pc.positionKey(pos)] = struct{}{}
}

// maybeFail checks a potential failure against a specific failure map.
func (pc *passContext) maybeFail(pos token.Pos, fmtStr string, args ...interface{}) {
	if fd, ok := pc.failures[pc.positionKey(pos)]; ok {
		fd.seen++
		return
	}
	if _, ok := pc.exemptions[pc.positionKey(pos)]; ok {
		return // Ignored, not counted.
	}
	pc.pass.Reportf(pos, fmtStr, args...)
}

// checkFailure checks for the expected failure counts.
func (pc *passContext) checkFailures() {
	for _, fd := range pc.failures {
		if fd.count != fd.seen {
			// We are missing expect failures, report as much as possible.
			pc.pass.Reportf(fd.pos, "got %d failures, want %d failures", fd.seen, fd.count)
		}
	}
}

// extractAnnotations extracts annotations from text.
func (pc *passContext) extractAnnotations(s string, fns map[string]func(p string)) {
	for prefix, fn := range fns {
		if strings.HasPrefix(s, prefix) {
			fn(s[len(prefix):])
		}
	}
}

// extractLineFailures extracts all line-based exceptions.
//
// Note that this applies only to individual line exemptions, and does not
// consider function-wide exemptions, or specific field exemptions, which are
// extracted separately as part of the saved facts for those objects.
func (pc *passContext) extractLineFailures() {
	for _, f := range pc.pass.Files {
		for _, cg := range f.Comments {
			for _, c := range cg.List {
				pc.extractAnnotations(c.Text, map[string]func(string){
					checkLocksFail:   func(p string) { pc.addFailures(c.Pos(), p) },
					checkLocksIgnore: func(string) { pc.addExemption(c.Pos()) },
					checkLocksForce:  func(string) { pc.addForce(c.Pos()) },
				})
			}
		}
	}
}
