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

// Package pagesizecheck asserts at build time that the page size selected for
// the non-Go parts of the build matches the page size the Go code was compiled
// for.
//
// Two independent flags select the page size:
//
//   - --define pagesize=64k drives select()s, and therefore the C sources
//     (for example sysmsg, which is compiled with -DPAGE_SIZE=65536).
//   - --go_tag=pagesize_64k drives Go build-tag source selection, and
//     therefore hostarch.PageSize.
//
// They cannot be derived from one another: //tools/build_defs/go:go_tag is a
// multi_string_set_flag, and config_setting.flag_values only matches scalar
// settings, so a --define cannot imply a Go build tag. Passing one without the
// other silently produces a binary whose C and Go halves disagree about the
// page size, which corrupts every page-size-derived offset at runtime.
//
// Linking this package into a binary turns that mismatch into a build failure.
// Import it for its side effects only:
//
//	import _ "gvisor.dev/gvisor/pkg/pagesizecheck"
package pagesizecheck

import (
	"gvisor.dev/gvisor/pkg/hostarch"
)

// definedPageSize reflects --define pagesize; hostarch.PageSize reflects
// --go_tag. Converting both differences to uint is only a valid constant
// expression when neither is negative, i.e. when the two are equal. A mismatch
// fails the build with "constant -61440 overflows uint".
const (
	definePageSizeMustNotExceedGoTagPageSize = uint(hostarch.PageSize - definedPageSize)
	goTagPageSizeMustNotExceedDefinePageSize = uint(definedPageSize - hostarch.PageSize)
)
