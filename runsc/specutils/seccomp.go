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

package specutils

import (
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// knownSeccompActions returns a list of all supported seccomp actions.
// Used by `runsc features`.
func knownSeccompActions() []string {
	// LINT.IfChange
	return []string{
		string(specs.ActKill),
		string(specs.ActTrap),
		string(specs.ActErrno),
		string(specs.ActTrace),
		string(specs.ActLog),
		string(specs.ActAllow),
	}
	// LINT.ThenChange(seccomp/seccomp.go:convertAction)
}

// knownSeccompOperators returns a list of all supported seccomp operators.
// Used by `runsc features`.
func knownSeccompOperators() []string {
	// LINT.IfChange
	return []string{
		string(specs.OpEqualTo),
		string(specs.OpNotEqual),
		string(specs.OpGreaterThan),
		string(specs.OpGreaterEqual),
		string(specs.OpLessThan),
		string(specs.OpLessEqual),
		string(specs.OpMaskedEqual),
	}
	// LINT.ThenChange(seccomp/seccomp.go:convertRule)
}

// knownSeccompArchs returns a list of all supported seccomp architectures.
// Used by `runsc features`.
func knownSeccompArchs() []string {
	// LINT.IfChange
	return []string{
		string(specs.ArchX86_64),
		string(specs.ArchAARCH64),
	}
	// LINT.ThenChange(seccomp/seccomp.go:lookupSyscallNo)
}

// knownSeccompFlags returns a list of all supported seccomp flags.
// Used by `runsc features`.
func knownSeccompFlags() []string {
	// LINT.IfChange
	return []string{
		"SECCOMP_FILTER_FLAG_TSYNC",
	}
	// LINT.ThenChange(../../test/syscalls/linux/seccomp.cc)
}

// supportedSeccompFlags returns a list of all supported seccomp flags.
// This list may be a subset of one returned by knownSeccompFlags.
// Used by `runsc features`.
func supportedSeccompFlags() []string {
	// LINT.IfChange
	return []string{
		"SECCOMP_FILTER_FLAG_TSYNC",
	}
	// LINT.ThenChange(../../test/syscalls/linux/seccomp.cc)
}
