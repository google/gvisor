// Copyright 2018 The gVisor Authors.
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

package kernel

import (
	"context"
	"math"

	"gvisor.dev/gvisor/pkg/tcpip"
)

// saveLiveTasks is invoked by stateify.
func (ts *TaskSet) saveLiveTasks() int64 {
	// The MSB, which is cleared by Kernel.WaitExited(), is never saved and is
	// always set again after restore, since whether Kernel.WaitExited() was
	// called before checkpointing is not intended to apply after restore.
	return ts.liveTasks.Load() &^ math.MinInt64
}

// loadLiveTasks is invoked by stateify.
func (ts *TaskSet) loadLiveTasks(_ context.Context, liveTasks int64) {
	ts.liveTasks.Store(liveTasks | math.MinInt64)
}

// afterLoad is invoked by stateify.
func (ts *TaskSet) afterLoad(_ context.Context) {
	ts.zeroLiveTasksC = make(chan struct{}, 0)
}

// saveDanglingEndpoints is invoked by stateify.
func (k *Kernel) saveDanglingEndpoints() []tcpip.Endpoint {
	return tcpip.GetDanglingEndpoints()
}

// loadDanglingEndpoints is invoked by stateify.
func (k *Kernel) loadDanglingEndpoints(_ context.Context, es []tcpip.Endpoint) {
	for _, e := range es {
		tcpip.AddDanglingEndpoint(e)
	}
}
