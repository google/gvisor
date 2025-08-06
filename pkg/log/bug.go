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
	"runtime"
	"strings"

	"gvisor.dev/gvisor/pkg/sync"
)

// This file contains helper functions analogous to the Linux kernel's WARN*
// macros. Should be used for non-fatal errors that should be treated as bugs
// none the less.

const (
	warnFmtStr         = "WARNING: BUG on %s:%d\n"
	warnUnknownLineStr = "WARNING: BUG on unknown line\n"
	catchAllMagic      = "runtime.Caller failed"
)

//go:noinline
func reportBugErr(caller int, err error) {
	reportBug(caller+1, err.Error(), nil)
}

func reportBug(caller int, msg string, vars []any) {
	var b strings.Builder
	if _, file, line, ok := runtime.Caller(caller); ok {
		b.WriteString(fmt.Sprintf(warnFmtStr, file, line))
	} else {
		b.WriteString(warnUnknownLineStr)
	}
	b.WriteByte('\n')
	if len(msg) > 0 {
		if len(vars) > 0 {
			b.WriteString(fmt.Sprintf(msg, vars...))
		} else {
			b.WriteString(msg)
		}
		b.WriteByte('\n')
	}
	TracebackAll(b.String())
}

var (
	// warnedMu protects the variables below.
	warnedMu sync.Mutex
	// warnedSet is used to keep track of which WarnOnOnce calls have fired.
	warnedSet map[string]struct{}
)

//go:noinline
func reportBugErrOnce(caller int, err error) {
	reportBugOnce(caller+1, err.Error(), nil)
}

func reportBugOnce(caller int, msg string, vars []any) {
	var b strings.Builder
	if _, file, line, ok := runtime.Caller(caller); ok {
		key := fmt.Sprintf("%s:%d", file, line)

		warnedMu.Lock()
		defer warnedMu.Unlock()

		if _, ok = warnedSet[key]; !ok {
			b.WriteString(fmt.Sprintf(warnFmtStr, file, line))
			b.WriteByte('\n')
			if len(msg) > 0 {
				if len(vars) > 0 {
					b.WriteString(fmt.Sprintf(msg, vars...))
				} else {
					b.WriteString(msg)
				}
				b.WriteByte('\n')
			}

			TracebackAll(b.String())
			warnedSet[key] = struct{}{}
		}
	} else {
		warnedMu.Lock()
		defer warnedMu.Unlock()

		// Use const string as a catch-all when runtime.Caller fails,
		// so as to avoid log-spam since that's the point of WARN_ONCE.
		if _, ok := warnedSet[catchAllMagic]; !ok {
			b.WriteString(warnUnknownLineStr)
			b.WriteByte('\n')
			if len(msg) > 0 {
				if len(vars) > 0 {
					b.WriteString(fmt.Sprintf(msg, vars...))
				} else {
					b.WriteString(msg)
				}
				b.WriteByte('\n')
			}

			TracebackAll(b.String())
			warnedSet[catchAllMagic] = struct{}{}
		}
	}
}

// BugTraceback will report a bug with a traceback of all goroutines if the
// error isn't nil. Use it for reporting abnormal bugs encountered at runtime
// that should be fixed.
//
// Do not use this for bad user input. Errors reported by this function should
// not be fatal.
func BugTraceback(err error) {
	if err != nil {
		reportBugErr(2, err)
	}
}

// BugTracebackf will report a bug with a traceback of all goroutines.
// Use it for reporting abnormal bugs encountered at runtime that should be
// fixed.
//
// Do not use this for bad user input. Errors reported by this function should
// not be fatal.
func BugTracebackf(s string, a ...any) {
	reportBug(2, s, a)
}

// BugTracebackOnce will report a bug with a traceback of all goroutines if the
// error isn't nil. Use it for reporting abnormal bugs encountered at runtime
// that should be fixed. If called multiple time from same invocation, will only
// print once.
//
// Do not use this for bad user input. Errors reported by this function should
// not be fatal.
func BugTracebackOnce(err error) {
	if err != nil {
		reportBugErrOnce(2, err)
	}
}

// BugTracebackfOnce will report a bug with a traceback of all goroutines.
// Use it for reporting abnormal bugs encountered at runtime that should be
// fixed. If called multiple time from same invocation, will only print once.
//
// Do not use this for bad user input. Errors reported by this function should
// not be fatal.
func BugTracebackfOnce(s string, a ...any) {
	reportBugOnce(2, s, a)
}
