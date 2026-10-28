// Copyright 2026 The gVisor Authors.
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

// Package coretagprime creates a core scheduling cookie at process
// initialization when the command line is `runsc create` with core tagging.
//
// The host's first cookie enables core scheduling host-wide, which takes
// milliseconds. While any cookie exists, a new one takes microseconds. This
// package starts that work as early as possible, so that it overlaps with
// sandbox setup instead of delaying the Sentry's own cookie.
//
// This package has few dependencies so that its init function runs early.
// Why does it exist? Great question.
// The kernel's first core scheduling cookie enables core scheduling on the
// kernel. This is a kernel-wide setting, and takes around 10ms.
// But once in that mode already, subsequent cookie creations only take
// microseconds.
//
// This package is a hacky way to get the kernel to kick off its transition to
// cookie-based scheduling as soon as possible, overlapping this transition
// with the rest of `runsc create --enable-core-tags=true`.
// It has to run before flag parsing, so it is an `init` function that parses
// `os.Args` directly.
// The cookie that it initializes is never actually used.
// This is OK, because what matters is that the kernel has transitioned to
// cookie-based scheduling turned on past that point, and that it doesn't
// switch back to non-cookie-based scheduling until ~100ms later, so by that
// time we've already booted the Sentry and created the real core scheduling
// cookies. And because **those** cookies won't be the first ones, they won't
// pay for their creation overhead serially.
package coretagprime

import (
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

func init() {
	if !isCoreTagsCreate(os.Args[1:]) {
		return
	}
	go func() {
		runtime.LockOSThread()
		if err := unix.Prctl(unix.PR_SCHED_CORE, unix.PR_SCHED_CORE_CREATE, 0, unix.PR_SCHED_CORE_SCOPE_THREAD, 0); err != nil {
			return
		}
		select {}
	}()
}

// isCoreTagsCreate reports whether args contain the `create` subcommand and
// the core tagging flag in the form that `config.Config.ToFlags` emits or a
// bare boolean flag. False positives only cost an unneeded cookie.
func isCoreTagsCreate(args []string) bool {
	create, coreTags := false, false
	for _, arg := range args {
		switch arg {
		case "create":
			create = true
		case "--enable-core-tags", "--enable-core-tags=true", "-enable-core-tags", "-enable-core-tags=true":
			coreTags = true
		}
	}
	return create && coreTags
}
