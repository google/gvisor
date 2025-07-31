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

const (
	warnFmtStr         = "WARNING: BUG on %s:%d\n"
	warnUnknownLineStr = "WARNING: BUG on unknown line\n"
	catchAllMagic      = "runtime.Caller failed"
)

func warn(caller int, msg string) {
	var b strings.Builder
	if _, file, line, ok := runtime.Caller(caller); ok {
		b.WriteString(fmt.Sprintf(warnFmtStr, file, line))
	} else {
		b.WriteString(warnUnknownLineStr)
	}
	b.WriteByte('\n')
	if len(msg) > 0 {
		b.WriteString(msg)
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

func warnOnce(caller int, msg string) {
	var b strings.Builder
	if _, file, line, ok := runtime.Caller(caller); ok {
		key := fmt.Sprintf("%s:%d", file, line)

		warnedMu.Lock()
		defer warnedMu.Unlock()

		if _, ok = warnedSet[key]; !ok {
			b.WriteString(fmt.Sprintf(warnFmtStr, file, line))
			b.WriteByte('\n')
			if len(msg) > 0 {
				b.WriteString(msg)
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
				b.WriteString(msg)
				b.WriteByte('\n')
			}

			TracebackAll(b.String())
			warnedSet[catchAllMagic] = struct{}{}
		}
	}
}

// WARN serves the same purpose as the Linux kernel's WARN macro. Use it
// for reporting abnormal bugs encountered at runtime that should be fixed.
//
// Will print out the full Go stacktrace at time of invocation.
//
// Do not use this for bad user input. Errors reported by this function should
// not be fatal.
func WARN(cond bool, s string, a ...any) {
	if !cond {
		return
	}
	msg := fmt.Sprintf(s, a...)
	warn(2, msg)
}

// WARN_ON serves the same purpose as the Linux kernel's WARN_ON macro. Use it
// for reporting abnormal bugs encountered at runtime that should be fixed.
//
// Will print out the full Go stacktrace at time of invocation.
//
// Do not use this for bad user input. Errors reported by this function should
// not be fatal.
func WARN_ON(cond bool) {
	if !cond {
		return
	}
	warn(2, "")
}

// WARN_ERR is a more Go-friendly version of the typical Linux WARN* macros. If
// the error isn't nil, it will report the error prefixed with the standard WARN
// string. Use it for reporting abnormal bugs encountered at runtime that
// should be fixed.
//
// Will print out the full Go stacktrace at time of invocation.
//
// Do not use this for bad user input. Errors reported by this function should
// not be fatal.
func WARN_ERR(err error) {
	if err == nil {
		return
	}
	warn(2, err.Error())
}

// WARN_ONCE serves the same purpose as the Linux kernel's WARN_ONCE macro.
// Use it for reporting abnormal bugs encountered at runtime that should be
// fixed.
//
// Will print out the full Go stacktrace at time of invocation.
//
// Do not use this for bad user input. Errors reported by this function should
// not be fatal.
func WARN_ONCE(cond bool, s string, a ...any) {
	if !cond {
		return
	}
	msg := fmt.Sprintf(s, a...)
	warnOnce(2, msg)
}

// WARN_ON_ONCE serves the same purpose as the Linux kernel's WARN_ON_ONCE macro.
// Use it for reporting abnormal bugs encountered at runtime that should be
// fixed.
//
// Will print out the full Go stacktrace at time of invocation.
//
// Do not use this for bad user input. Errors reported by this function should
// not be fatal.
func WARN_ON_ONCE(cond bool) {
	if !cond {
		return
	}
	warnOnce(2, "")
}

// WARN_ERR_ONCE is a more Go-friendly version of the typical Linux WARN* macros.
// If the error isn't nil, it will report the error prefixed with the standard
// WARN string. Use it for reporting abnormal bugs encountered at runtime that
// should be fixed.
//
// Will print out the full Go stacktrace at time of invocation.
//
// Do not use this for bad user input. Errors reported by this function should
// not be fatal.
func WARN_ERR_ONCE(err error) {
	if err == nil {
		return
	}
	warnOnce(2, err.Error())
}
