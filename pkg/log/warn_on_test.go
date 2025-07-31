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
			WARN_ON(false)
			if len(tw.lines) > 0 {
				t.Errorf("WARN_ON printed when it shouldn't have")
			}

			WARN_ON(true)
			if len(tw.lines) == 0 {
				t.Errorf("WARN_ON didn't print anything when it should have")
			}
		},
		"testStringFormat": func(t *testing.T) {
			expectFile := "pkg/log/warn_on_test.go"
			// Don't try to match the line to make this test less
			// brittle to somebody accidentally sneezing on this file.
			expectStr := strings.SplitN(warnFmtStr, "%", 2)[0]

			WARN_ON(true)

			if len(tw.lines) == 0 {
				t.Errorf("WARN_ON didn't print anything when it should have")
			}
			if !strings.Contains(tw.lines[0], expectFile) {
				t.Errorf("WARN_ON didn't contain expected output, expected: '%s', got: '%s'", expectFile, tw.lines[0])
			}
			if !strings.Contains(tw.lines[0], expectStr) {
				t.Errorf("WARN_ON didn't contain expected output, expected: '%s', got: '%s'", expectStr, tw.lines[0])
			}
		},
		"testCustomFormat": func(t *testing.T) {
			expectFile := "pkg/log/warn_on_test.go"
			expectStr1 := strings.SplitN(warnFmtStr, "%", 2)[0]
			expectStr2 := "This is just a test warning"
			WARN(true, "This is just a test warning")

			if len(tw.lines) == 0 {
				t.Errorf("WARN_ON didn't print anything when it should have")
			}
			if !strings.Contains(tw.lines[0], expectFile) {
				t.Errorf("WARN_ON didn't contain expected output, expected: '%s', got: '%s'", expectFile, tw.lines[0])
			}
			if !strings.Contains(tw.lines[0], expectStr1) {
				t.Errorf("WARN_ON didn't contain expected output, expected: '%s', got: '%s'", expectStr1, tw.lines[0])
			}
			if !strings.Contains(tw.lines[0], expectStr2) {
				t.Errorf("WARN_ON didn't contain expected output, expected: '%s', got: '%s'", expectStr2, tw.lines[0])
			}
		},
		"testWarnErr": func(t *testing.T) {
			expectFile := "pkg/log/warn_on_test.go"
			expectStr1 := strings.SplitN(warnFmtStr, "%", 2)[0]
			expectStr2 := "My little error string"
			var err error
			WARN_ERR(err)
			if len(tw.lines) > 0 {
				t.Errorf("WARN_ON printed when it shouldn't have")
			}

			err = fmt.Errorf("My little error string")
			WARN_ERR(err)
			if len(tw.lines) == 0 {
				t.Errorf("WARN_ON didn't print anything when it should have")
			}
			if !strings.Contains(tw.lines[0], expectFile) {
				t.Errorf("WARN_ON didn't contain expected output, expected: '%s', got: '%s'", expectFile, tw.lines[0])
			}
			if !strings.Contains(tw.lines[0], expectStr1) {
				t.Errorf("WARN_ON didn't contain expected output, expected: '%s', got: '%s'", expectStr1, tw.lines[0])
			}
			if !strings.Contains(tw.lines[0], expectStr2) {
				t.Errorf("WARN_ON didn't contain expected output, expected: '%s', got: '%s'", expectStr2, tw.lines[0])
			}
		},
		"testWarnOnceOnlyPrintsOnce": func(t *testing.T) {
			testHelperFunc := func() {
				WARN_ON_ONCE(true)
			}

			testHelperFunc()
			if len(tw.lines) == 0 {
				t.Errorf("WarnOnOnce didn't print anything when it should have")
			}
			tw.clear()

			testHelperFunc()
			if len(tw.lines) > 0 {
				t.Errorf("WarnOnOnce printed out a warning a second time when it shouldn't have")
			}
		},
		"testWarnOnceDoesntClobberOthers": func(t *testing.T) {
			WARN_ON_ONCE(true)
			if len(tw.lines) == 0 {
				t.Errorf("First WarnOnOnce didn't print anything when it should have")
			}
			tw.clear()

			WARN_ON_ONCE(true)
			if len(tw.lines) == 0 {
				t.Errorf("Second WarnOnOnce didn't print anything when it should have")
			}
		},
	}
	for name, tc := range testCases {
		tw.clear()
		t.Run(name, tc)
	}
}
