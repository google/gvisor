// Copyright 2017 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build amd64

package sleep

// See commit_noasm.go for a description of commitSleep.
func commitSleep(g uintptr, waitingG *uintptr) bool
