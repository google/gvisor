// Copyright 2009 The Go Authors. All rights reserved.
// Copyright 2019 The gVisor Authors.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build go1.13
// +build !go1.14

// Check go:linkname function signatures when updating Go version.

package gvsync

import _ "unsafe"

//go:linkname runtimeSemrelease sync.runtime_Semrelease
func runtimeSemrelease(s *uint32, handoff bool, skipframes int)
