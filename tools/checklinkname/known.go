// Copyright 2021 The gVisor Authors.
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

package checklinkname

// knownLinknames is the set of the symbols for which we can do a rudimentary
// type-check on.
//
// When analyzing the remote package (e.g., runtime), we verify the symbol
// signature matches 'remote'. When analyzing local packages with //go:linkname
// directives, we verify the symbol signature matches 'local'.
//
// Usually these are identical, but may differ slightly if equivalent
// replacement types are used in the local packages, such as a copy of a struct
// or uintptr instead of a pointer type.
//
// NOTE: It is the responsibility of the developer to verify the safety of the
// signatures used here! This analyzer only checks that types match this map;
// it does not verify compatibility of the entries themselves.
//
// //go:linkname directives with no corresponding entry here will trigger a
// finding.
//
// We preform only rudimentary string-based type-checking due to limitations in
// the analysis framework. Ideally, from the local package we'd lookup the
// remote symbol's types.Object and perform robust type-checking.
// Unfortunately, remote symbols are typically loaded from the remote package's
// gcexportdata. Since //go:linkname targets are usually not exported symbols,
// they are no included in gcexportdata and we cannot load their types.Object.
//
// TODO(b/165820485): Add option to specific per-version signatures.
var knownLinknames = map[string]map[string]linknameSignatures{
	"runtime": {
		"cputicks": {
			local: "func() int64",
		},
		"entersyscall": {
			local: "func()",
		},
		"entersyscallblock": {
			local: "func()",
		},
		"exitsyscall": {
			local: "func()",
		},
		"fastrand": {
			local: "func() uint32",
		},
		"gopark": {
			// TODO(b/165820485): add verification of waitReason
			// size and reason and traceEv values.
			local:  "func(unlockf func(uintptr, unsafe.Pointer) bool, lock unsafe.Pointer, reason uint8, traceEv byte, traceskip int)",
			remote: "func(unlockf func(*runtime.g, unsafe.Pointer) bool, lock unsafe.Pointer, reason runtime.waitReason, traceEv byte, traceskip int)",
		},
		"goready": {
			local:  "func(gp uintptr, traceskip int)",
			remote: "func(gp *runtime.g, traceskip int)",
		},
		"goyield": {
			local: "func()",
		},
		"memmove": {
			local: "func(to unsafe.Pointer, from unsafe.Pointer, n uintptr)",
		},
		"throw": {
			local: "func(s string)",
		},
		"wakep": {
			local: "func()",
		},
		"nanotime": {
			local: "func() int64",
		},
	},
	"sync": {
		"runtime_canSpin": {
			local: "func(i int) bool",
		},
		"runtime_doSpin": {
			local: "func()",
		},
		"runtime_Semacquire": {
			// The only difference here is the parameter names. We
			// can't just change our local use to match remote, as
			// the stdlib runtime and sync packages also disagree
			// on the name, and the analyzer checks that use as
			// well.
			local:  "func(addr *uint32)",
			remote: "func(s *uint32)",
		},
		"runtime_Semrelease": {
			// See above.
			local:  "func(addr *uint32, handoff bool, skipframes int)",
			remote: "func(s *uint32, handoff bool, skipframes int)",
		},
	},
	"syscall": {
		"runtime_BeforeFork": {
			local: "func()",
		},
		"runtime_AfterFork": {
			local: "func()",
		},
		"runtime_AfterForkInChild": {
			local: "func()",
		},
	},
}
