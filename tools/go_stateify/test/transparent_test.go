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

package test

import (
	"bytes"
	"context"
	"slices"
	"testing"

	"gvisor.dev/gvisor/pkg/state"
	"gvisor.dev/gvisor/tools/go_stateify/test/external"
)

func TestTransparentWrapperRoundTrip(t *testing.T) {
	ctx := context.Background()
	original := intBox{box[int]{Value: 42}}
	if got, want := original.StateTypeName(), "tools/go_stateify/test.intBox"; got != want {
		t.Fatalf("StateTypeName()=%q, want %q", got, want)
	}
	if got, want := original.StateFields(), []string{"Value"}; !slices.Equal(got, want) {
		t.Fatalf("StateFields()=%q, want %q", got, want)
	}

	var buf bytes.Buffer
	if _, err := state.Save(ctx, &buf, &original); err != nil {
		t.Fatalf("Save failed: %s", err)
	}

	var restored intBox
	if _, err := state.Load(ctx, &buf, &restored); err != nil {
		t.Fatalf("Load failed: %s", err)
	}
	if restored.Value != original.Value {
		t.Fatalf("restored.Value=%d, want %d", restored.Value, original.Value)
	}
}

func TestTransparentWrapperCrossPackage(t *testing.T) {
	ctx := context.Background()
	original := externalIntBox{external.Box[int]{Value: 7}}
	if got, want := original.StateTypeName(), "tools/go_stateify/test.externalIntBox"; got != want {
		t.Fatalf("StateTypeName()=%q, want %q", got, want)
	}
	if got, want := original.StateFields(), []string{"Value"}; !slices.Equal(got, want) {
		t.Fatalf("StateFields()=%q, want %q", got, want)
	}

	var buf bytes.Buffer
	if _, err := state.Save(ctx, &buf, &original); err != nil {
		t.Fatalf("Save failed: %s", err)
	}

	var restored externalIntBox
	if _, err := state.Load(ctx, &buf, &restored); err != nil {
		t.Fatalf("Load failed: %s", err)
	}
	if restored.Value != original.Value {
		t.Fatalf("restored.Value=%d, want %d", restored.Value, original.Value)
	}
}

func TestTransparentWrapperPlain(t *testing.T) {
	ctx := context.Background()
	original := plainBoxWrapper{plainBox{Value: 5}}
	if got, want := original.StateTypeName(), "tools/go_stateify/test.plainBoxWrapper"; got != want {
		t.Fatalf("StateTypeName()=%q, want %q", got, want)
	}
	if got, want := original.StateFields(), []string{"Value"}; !slices.Equal(got, want) {
		t.Fatalf("StateFields()=%q, want %q", got, want)
	}

	var buf bytes.Buffer
	if _, err := state.Save(ctx, &buf, &original); err != nil {
		t.Fatalf("Save failed: %s", err)
	}

	var restored plainBoxWrapper
	if _, err := state.Load(ctx, &buf, &restored); err != nil {
		t.Fatalf("Load failed: %s", err)
	}
	if restored.Value != original.Value {
		t.Fatalf("restored.Value=%d, want %d", restored.Value, original.Value)
	}
}
