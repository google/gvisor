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

	"gvisor.dev/gvisor/pkg/tcpip"
)

// afterLoad is invoked by stateify.
func (ts *TaskSet) afterLoad(_ context.Context) {
	ts.zeroLiveTasksCond.L = &ts.mu
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

// saveVforkParent is invoked by stateify.
func (t *Task) saveVforkParent() *Task {
	return t.vforkParent.Load()
}

// loadVforkParent is invoked by stateify.
func (t *Task) loadVforkParent(_ context.Context, vforkParent *Task) {
	t.vforkParent.Store(vforkParent)
}

// savePtraceTracer is invoked by stateify.
func (t *Task) savePtraceTracer() *Task {
	return t.ptraceTracer.Load()
}

// loadPtraceTracer is invoked by stateify.
func (t *Task) loadPtraceTracer(_ context.Context, tracer *Task) {
	t.ptraceTracer.Store(tracer)
}

// saveSeccomp is invoked by stateify.
func (t *Task) saveSeccomp() *taskSeccomp {
	return t.seccomp.Load()
}

// loadSeccomp is invoked by stateify.
func (t *Task) loadSeccomp(_ context.Context, seccompData *taskSeccomp) {
	t.seccomp.Store(seccompData)
}

// saveAppCPUClockLast is invoked by stateify.
func (tg *ThreadGroup) saveAppCPUClockLast() *Task {
	return tg.appCPUClockLast.Load()
}

// loadAppCPUClockLast is invoked by stateify.
func (tg *ThreadGroup) loadAppCPUClockLast(_ context.Context, task *Task) {
	tg.appCPUClockLast.Store(task)
}

// saveAppSysCPUClockLast is invoked by stateify.
func (tg *ThreadGroup) saveAppSysCPUClockLast() *Task {
	return tg.appSysCPUClockLast.Load()
}

// loadAppSysCPUClockLast is invoked by stateify.
func (tg *ThreadGroup) loadAppSysCPUClockLast(_ context.Context, task *Task) {
	tg.appSysCPUClockLast.Store(task)
}

// saveOldRSeqCritical is invoked by stateify.
func (tg *ThreadGroup) saveOldRSeqCritical() *OldRSeqCriticalRegion {
	return tg.oldRSeqCritical.Load()
}

// loadOldRSeqCritical is invoked by stateify.
func (tg *ThreadGroup) loadOldRSeqCritical(_ context.Context, r *OldRSeqCriticalRegion) {
	tg.oldRSeqCritical.Store(r)
}
