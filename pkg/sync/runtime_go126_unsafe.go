// Copyright 2024 The gVisor Authors.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd.

// https://go.dev/cl/691596 (1.26) renames the internal map type which nogo relies on.
//go:build go1.26

package sync

import "unsafe"

// Use checkoffset to assert that maptype.hasher (the only field we use) has
// the correct offset.
const maptypeHasherOffset = unsafe.Offsetof(maptype{}.Hasher) // +checkoffset internal/abi MapType.Hasher
