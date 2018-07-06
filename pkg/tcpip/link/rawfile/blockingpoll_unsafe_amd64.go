// Copyright 2018 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build linux,amd64

package rawfile

import (
	"syscall"
)

//go:noescape
func blockingPoll(fds *pollEvent, nfds int, timeout int64) (int, syscall.Errno)
