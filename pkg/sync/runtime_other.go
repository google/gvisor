// Copyright 2020 The gVisor Authors.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd.

//go:build !amd64
// +build !amd64

package sync

const supportsWakeSuppression = false

func preGoReadyWakeSuppression()  {} // Never called.
func postGoReadyWakeSuppression() {} // Never called.
