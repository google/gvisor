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

//go:build arm64 && !pagesize_64k
// +build arm64,!pagesize_64k

package kvm

// _TCR_TG_FLAGS selects the translation granule used by the guest page
// tables, which must match the granule the pagetables package was built
// for (see pkg/ring0/pagetables/pagetables_arm64_4k.go).
const _TCR_TG_FLAGS = _TCR_TG0_4K | _TCR_TG1_4K
