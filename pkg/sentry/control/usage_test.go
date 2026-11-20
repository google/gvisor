// Copyright 2026 The gVisor Authors.
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

package control

import (
	"testing"

	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/control/controlapi"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/testutil"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
)

func TestUsageCollect(t *testing.T) {
	k, err := testutil.Boot()
	if err != nil {
		t.Fatalf("testutil.Boot() failed: %v", err)
	}
	defer k.Timekeeper().Destroy()
	k.GlobalInit().Release(k.SupervisorContext())
	k.TestOnlySetGlobalInit(nil)

	mf := k.MemoryFile()
	fr, err := mf.Allocate(uint64(hostarch.PageSize), pgalloc.AllocOpts{Mode: pgalloc.AllocateAndCommit})
	if err != nil {
		t.Fatalf("MemoryFile.Allocate failed: %v", err)
	}
	defer mf.DecRef(fr)

	u := &Usage{Kernel: k}

	var partialOut controlapi.MemoryUsage
	if err := u.Collect(&controlapi.MemoryUsageOpts{Full: false}, &partialOut); err != nil {
		t.Fatalf("Usage.Collect(Full: false) failed: %v", err)
	}
	if partialOut.Unknown == 0 {
		t.Errorf("Usage.Collect(Full: false) Unknown = 0, want > 0")
	}

	var fullOut controlapi.MemoryUsage
	if err := u.Collect(&controlapi.MemoryUsageOpts{Full: true}, &fullOut); err != nil {
		t.Fatalf("Usage.Collect(Full: true) failed: %v", err)
	}
	if fullOut.Total == 0 {
		t.Errorf("Usage.Collect(Full: true) Total = 0, want > 0")
	}

	mf.File().Close()
	if err := u.Collect(&controlapi.MemoryUsageOpts{Full: true}, &fullOut); err == nil {
		t.Errorf("Usage.Collect(Full: true) on closed file succeeded, want error")
	}
}
