// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stack

// StackFromEnv is the global stack created in restore run.
// FIXME: remove this variable once tcpip S/R is fully supported.
var StackFromEnv *Stack
