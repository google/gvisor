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

// Package contexttest provides a test context.Context which includes
// a dummy kernel pointing to a valid platform.
package contexttest

import (
	"testing"

	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context/contexttest"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/pgalloc"
	"gvisor.googlesource.com/gvisor/pkg/sentry/platform"
)

// Context returns a Context that may be used in tests. Uses ptrace as the
// platform.Platform, and provides a stub kernel that only serves to point to
// the platform.
func Context(tb testing.TB) context.Context {
	ctx := contexttest.Context(tb)
	k := &kernel.Kernel{
		Platform: platform.FromContext(ctx),
	}
	k.SetMemoryFile(pgalloc.MemoryFileFromContext(ctx))
	ctx.(*contexttest.TestContext).RegisterValue(kernel.CtxKernel, k)
	return ctx
}
