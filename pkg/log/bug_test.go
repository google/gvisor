// Copyright 2025 The gVisor Authors.
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

package log

import (
	"fmt"
	"strings"
	"testing"
)

const expectFile = "pkg/log/bug_test.go"

func TestWarnOn(t *testing.T) {
	tw := &testWriter{}
	e := GoogleEmitter{Writer: &Writer{Next: tw}}
	bl := &BasicLogger{
		Emitter: e,
		Level:   Debug,
	}
	old := Log()
	log.Store(bl)
	defer log.Store(old)

	testCases := map[string]func(t *testing.T){
		"testConditionControlsPrint": func(t *testing.T) {
			BugTracebackOn(false)
			if len(tw.lines) > 0 {
				t.Errorf("BugTracebackOn printed when it shouldn't have")
			}

			BugTracebackOn(true)
			if len(tw.lines) == 0 {
				t.Errorf("BugTracebackOn didn't print anything when it should have")
			}
		},
		"testStringFormat": func(t *testing.T) {
			// Don't try to match the line to make this test less
			// brittle to somebody accidentally sneezing on this file.
			expectStr := strings.SplitN(warnFmtStr, "%", 2)[0]

			BugTracebackOn(true)

			if len(tw.lines) == 0 {
				t.Errorf("BugTracebackOn didn't print anything when it should have")
			}
			if !strings.Contains(tw.lines[0], expectFile) {
				t.Errorf("BugTracebackOn didn't contain expected output, expected: '%s', got: '%s'", expectFile, tw.lines[0])
			}
			if !strings.Contains(tw.lines[0], expectStr) {
				t.Errorf("BugTracebackOn didn't contain expected output, expected: '%s', got: '%s'", expectStr, tw.lines[0])
			}
		},
		"testCustomFormat": func(t *testing.T) {
			expectStr1 := strings.SplitN(warnFmtStr, "%", 2)[0]
			expectStr2 := "This is just a test warning"
			BugTracebackf(true, "This is just a test warning: %s", "with another var string")

			if len(tw.lines) == 0 {
				t.Errorf("BugTracebackf didn't print anything when it should have")
			}
			if !strings.Contains(tw.lines[0], expectFile) {
				t.Errorf("BugTracebackf didn't contain expected output, expected: '%s', got: '%s'", expectFile, tw.lines[0])
			}
			if !strings.Contains(tw.lines[0], expectStr1) {
				t.Errorf("BugTracebackf didn't contain expected output, expected: '%s', got: '%s'", expectStr1, tw.lines[0])
			}
			if !strings.Contains(tw.lines[0], expectStr2) {
				t.Errorf("BugTracebackf didn't contain expected output, expected: '%s', got: '%s'", expectStr2, tw.lines[0])
			}
		},
		"testWarnErr": func(t *testing.T) {
			expectStr1 := strings.SplitN(warnFmtStr, "%", 2)[0]
			expectStr2 := "My little error string"
			var err error
			BugTraceback(err)
			if len(tw.lines) > 0 {
				t.Errorf("BugTraceback printed when it shouldn't have")
			}

			err = fmt.Errorf("My little error string")
			BugTraceback(err)
			if len(tw.lines) == 0 {
				t.Errorf("BugTraceback didn't print anything when it should have")
			}
			if !strings.Contains(tw.lines[0], expectFile) {
				t.Errorf("BugTraceback didn't contain expected output, expected: '%s', got: '%s'", expectFile, tw.lines[0])
			}
			if !strings.Contains(tw.lines[0], expectStr1) {
				t.Errorf("BugTraceback didn't contain expected output, expected: '%s', got: '%s'", expectStr1, tw.lines[0])
			}
			if !strings.Contains(tw.lines[0], expectStr2) {
				t.Errorf("BugTraceback didn't contain expected output, expected: '%s', got: '%s'", expectStr2, tw.lines[0])
			}
		},
		"testWarnOnceOnlyPrintsOnce": func(t *testing.T) {
			testHelperFunc := func() {
				BugTracebackOnceOn(true)
			}

			testHelperFunc()
			if len(tw.lines) == 0 {
				t.Errorf("BugTracebackOnceOn didn't print anything when it should have")
			}
			tw.clear()

			testHelperFunc()
			if len(tw.lines) > 0 {
				t.Errorf("BugTracebackOnceOn printed out a warning a second time when it shouldn't have")
			}
		},
		"testWarnOnceDoesntClobberOthers": func(t *testing.T) {
			BugTracebackOnceOn(true)
			if len(tw.lines) == 0 {
				t.Errorf("First BugTracebackOnceOn didn't print anything when it should have")
			}
			tw.clear()

			BugTracebackOnceOn(true)
			if len(tw.lines) == 0 {
				t.Errorf("Second BugTracebackOnceOn didn't print anything when it should have")
			}
		},
	}
	for name, tc := range testCases {
		tw.clear()
		t.Run(name, tc)
	}
}
