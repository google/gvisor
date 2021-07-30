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

// Package test provides linkname test targets.
package test

import (
	_ "unsafe" // for go:linkname.
)

//go:linkname DetachedLinkname runtime.fastrand

//go:linkname attachedLinkname runtime.entersyscall
func attachedLinkname()

// AttachedLinkname reexports attachedLinkname because go vet doesn't like an
// exported go:linkname without a comment starting with "// AttachedLinkname".
func AttachedLinkname() {
	attachedLinkname()
}

// DetachedLinkname has a linkname elsewhere in the file.
func DetachedLinkname() uint32
