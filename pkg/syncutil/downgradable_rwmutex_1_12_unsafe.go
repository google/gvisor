// Copyright 2009 The Go Authors. All rights reserved.
// Copyright 2019 The gVisor Authors.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build go1.12
// +build !go1.13

// TODO(b/133868570): Delete once Go 1.12 is no longer supported.

package syncutil

import _ "unsafe"

//go:linkname runtimeSemrelease112 sync.runtime_Semrelease
func runtimeSemrelease112(s *uint32, handoff bool)

func runtimeSemrelease(s *uint32, handoff bool, skipframes int) {
	// 'skipframes' is only available starting from 1.13.
	runtimeSemrelease112(s, handoff)
}
