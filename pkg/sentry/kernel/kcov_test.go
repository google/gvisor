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

package kernel

import (
	"bytes"
	"context"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/state"
)

func TestKcovSaveRestore(t *testing.T) {
	original := &Kcov{mf: new(pgalloc.MemoryFile)}
	const size = uint64(hostarch.PageSize / 8)
	if err := original.InitTrace(size); err != nil {
		t.Fatal(err)
	}
	var data bytes.Buffer
	if _, err := state.Save(t.Context(), &data, &original); err != nil {
		t.Fatal(err)
	}

	mf := new(pgalloc.MemoryFile)
	ctx := context.WithValue(t.Context(), pgalloc.CtxMemoryFile, mf)
	var restored *Kcov
	if _, err := state.Load(ctx, &data, &restored); err != nil {
		t.Fatal(err)
	}
	if got, want := restored.mf, mf; got != want {
		t.Errorf("restored memory file = %p, want %p", got, want)
	}
	restored.mu.Lock()
	defer restored.mu.Unlock()
	if got, want := restored.mode, uint8(linux.KCOV_MODE_INIT); got != want {
		t.Errorf("restored mode = %d, want %d", got, want)
	}
	if got, want := restored.size, size; got != want {
		t.Errorf("restored size = %d, want %d", got, want)
	}
}
