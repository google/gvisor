// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package proc

import (
	"errors"
	"strings"
	"testing"

	"github.com/containerd/containerd/v2/pkg/protobuf/types"
	"github.com/containerd/containerd/v2/pkg/stdio"
	"github.com/containerd/errdefs"
	"gvisor.dev/gvisor/pkg/shim/v1/runsccmd"
)

func TestInitUpdateNilAny(t *testing.T) {
	p := New("id", &runsccmd.Runsc{}, stdio.Stdio{})
	p.initState = &runningState{p: p}
	err := p.Update(t.Context(), nil)
	if !errors.Is(err, errdefs.ErrInvalidArgument) {
		t.Fatalf("Update(nil): %v, want ErrInvalidArgument", err)
	}
}

func TestInitUpdateInvalidJSON(t *testing.T) {
	p := New("id", &runsccmd.Runsc{}, stdio.Stdio{})
	p.initState = &runningState{p: p}
	err := p.Update(t.Context(), &types.Any{Value: []byte(`{`)})
	if err == nil || !strings.Contains(err.Error(), "decoding resources") {
		t.Fatalf("Update(bad JSON): %v", err)
	}
}
