// Copyright 2018 The gVisor Authors.
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

// Package hosttid provides the Current function.
package hosttid

import (
	"runtime"
)

// Dummy references for facts.
const _ = runtime.Compiler

// Current returns the caller's host thread ID. Unless runtime.LockOSThread()
// is in effect, this function is inherently racy since the Go runtime may
// migrate the calling goroutine to another thread at any time.
//
// Current is equivalent to unix.Gettid(), but faster.
func Current() uint64
