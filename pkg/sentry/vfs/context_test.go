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

package vfs

import (
	goContext "context"
	"io"
	"testing"

	"gvisor.dev/gvisor/pkg/sentry/checkpoint"
)

type dummyTarProvider struct{}

func (dummyTarProvider) GetFSTar(id checkpoint.ResourceID) (io.ReadCloser, error) {
	return nil, nil
}

func TestFSTarProviderFromContext(t *testing.T) {
	// 1. Missing key in context returns nil.
	ctx := goContext.Background()
	if got := FSTarProviderFromContext(ctx); got != nil {
		t.Errorf("FSTarProviderFromContext(empty) = %v, want nil", got)
	}

	// 2. Valid FSTarProvider returns the provider.
	expected := dummyTarProvider{}
	ctxWithValid := goContext.WithValue(ctx, CtxFSTarProvider, expected)
	if got := FSTarProviderFromContext(ctxWithValid); got != expected {
		t.Errorf("FSTarProviderFromContext(valid) = %v, want %v", got, expected)
	}

	// 3. Invalid / unexpected type in context returns nil without panicking.
	ctxWithWrongType := goContext.WithValue(ctx, CtxFSTarProvider, "not-a-provider")
	if got := FSTarProviderFromContext(ctxWithWrongType); got != nil {
		t.Errorf("FSTarProviderFromContext(wrong-type) = %v, want nil", got)
	}
}
