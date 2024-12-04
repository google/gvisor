// Copyright 2024 The gVisor Authors.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.24

package sync

import "unsafe"

// Use checkoffset to assert that maptype.hasher (the only field we use) has
// the correct offset.
const maptypeHasherOffset = unsafe.Offsetof(maptype{}.Hasher) // +checkoffset internal/abi SwissMapType.Hasher
