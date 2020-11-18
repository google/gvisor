// Copyright 2020 The gVisor Authors.
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

// Package locks defines the global lock ordering for gVisor.
package locks

import (
	"gvisor.dev/gvisor/pkg/sync"
)

// Global lock ranking. Locks with higher rank must be taken after locks with
// lower rank.
const (
	// Rank 0 is reserved for use by zero-value mutexes.
	reserved = iota

	// p9 server locks.
	P9ConnFID
	P9ServerRename
	P9PathNodeOp
	P9PathNodeChild

	// p9test locks.
	P9TestGlobal
	P9TestHarness
)

func init() {
	// p9 server locks.
	sync.RegisterRank(P9ConnFID, "p9.connState.fidMu")
	sync.RegisterRank(P9ServerRename, "p9.Server.renameMu")
	sync.RegisterRank(P9PathNodeOp, "p9.pathNode.opMu")
	sync.RegisterRank(P9PathNodeChild, "p9.pathNode.childMu")

	// p9test locks.
	sync.RegisterRank(P9TestGlobal, "p9test.globalMu")
	sync.RegisterRank(P9TestHarness, "p9test.Harness.mu")
}
