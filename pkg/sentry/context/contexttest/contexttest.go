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

// Package contexttest builds a test context.Context.
package contexttest

import (
	"os"
	"sync/atomic"
	"testing"
	"time"

	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/auth"
	ktime "gvisor.googlesource.com/gvisor/pkg/sentry/kernel/time"
	"gvisor.googlesource.com/gvisor/pkg/sentry/limits"
	"gvisor.googlesource.com/gvisor/pkg/sentry/memutil"
	"gvisor.googlesource.com/gvisor/pkg/sentry/pgalloc"
	"gvisor.googlesource.com/gvisor/pkg/sentry/platform"
	"gvisor.googlesource.com/gvisor/pkg/sentry/platform/ptrace"
	"gvisor.googlesource.com/gvisor/pkg/sentry/uniqueid"
)

// Context returns a Context that may be used in tests. Uses ptrace as the
// platform.Platform.
//
// Note that some filesystems may require a minimal kernel for testing, which
// this test context does not provide. For such tests, see kernel/contexttest.
func Context(tb testing.TB) context.Context {
	const memfileName = "contexttest-memory"
	memfd, err := memutil.CreateMemFD(memfileName, 0)
	if err != nil {
		tb.Fatalf("error creating application memory file: %v", err)
	}
	memfile := os.NewFile(uintptr(memfd), memfileName)
	mf, err := pgalloc.NewMemoryFile(memfile, pgalloc.MemoryFileOpts{})
	if err != nil {
		memfile.Close()
		tb.Fatalf("error creating pgalloc.MemoryFile: %v", err)
	}
	p, err := ptrace.New()
	if err != nil {
		tb.Fatal(err)
	}
	// Test usage of context.Background is fine.
	return &TestContext{
		Context:     context.Background(),
		l:           limits.NewLimitSet(),
		mf:          mf,
		platform:    p,
		otherValues: make(map[interface{}]interface{}),
	}
}

// TestContext represents a context with minimal functionality suitable for
// running tests.
type TestContext struct {
	context.Context
	l           *limits.LimitSet
	mf          *pgalloc.MemoryFile
	platform    platform.Platform
	otherValues map[interface{}]interface{}
}

// globalUniqueID tracks incremental unique identifiers for tests.
var globalUniqueID uint64

// globalUniqueIDProvider implements unix.UniqueIDProvider.
type globalUniqueIDProvider struct{}

// UniqueID implements unix.UniqueIDProvider.UniqueID.
func (*globalUniqueIDProvider) UniqueID() uint64 {
	return atomic.AddUint64(&globalUniqueID, 1)
}

// lastInotifyCookie is a monotonically increasing counter for generating unique
// inotify cookies. Must be accessed using atomic ops.
var lastInotifyCookie uint32

// hostClock implements ktime.Clock.
type hostClock struct {
	ktime.WallRateClock
	ktime.NoClockEvents
}

// Now implements ktime.Clock.Now.
func (hostClock) Now() ktime.Time {
	return ktime.FromNanoseconds(time.Now().UnixNano())
}

// RegisterValue registers additional values with this test context. Useful for
// providing values from external packages that contexttest can't depend on.
func (t *TestContext) RegisterValue(key, value interface{}) {
	t.otherValues[key] = value
}

// Value implements context.Context.
func (t *TestContext) Value(key interface{}) interface{} {
	switch key {
	case limits.CtxLimits:
		return t.l
	case pgalloc.CtxMemoryFile:
		return t.mf
	case pgalloc.CtxMemoryFileProvider:
		return t
	case platform.CtxPlatform:
		return t.platform
	case uniqueid.CtxGlobalUniqueID:
		return (*globalUniqueIDProvider).UniqueID(nil)
	case uniqueid.CtxGlobalUniqueIDProvider:
		return &globalUniqueIDProvider{}
	case uniqueid.CtxInotifyCookie:
		return atomic.AddUint32(&lastInotifyCookie, 1)
	case ktime.CtxRealtimeClock:
		return hostClock{}
	default:
		if val, ok := t.otherValues[key]; ok {
			return val
		}
		return t.Context.Value(key)
	}
}

// MemoryFile implements pgalloc.MemoryFileProvider.MemoryFile.
func (t *TestContext) MemoryFile() *pgalloc.MemoryFile {
	return t.mf
}

// RootContext returns a Context that may be used in tests that need root
// credentials. Uses ptrace as the platform.Platform.
func RootContext(tb testing.TB) context.Context {
	return WithCreds(Context(tb), auth.NewRootCredentials(auth.NewRootUserNamespace()))
}

// WithCreds returns a copy of ctx carrying creds.
func WithCreds(ctx context.Context, creds *auth.Credentials) context.Context {
	return &authContext{ctx, creds}
}

type authContext struct {
	context.Context
	creds *auth.Credentials
}

// Value implements context.Context.
func (ac *authContext) Value(key interface{}) interface{} {
	switch key {
	case auth.CtxCredentials:
		return ac.creds
	default:
		return ac.Context.Value(key)
	}
}

// WithLimitSet returns a copy of ctx carrying l.
func WithLimitSet(ctx context.Context, l *limits.LimitSet) context.Context {
	return limitContext{ctx, l}
}

type limitContext struct {
	context.Context
	l *limits.LimitSet
}

// Value implements context.Context.
func (lc limitContext) Value(key interface{}) interface{} {
	switch key {
	case limits.CtxLimits:
		return lc.l
	default:
		return lc.Context.Value(key)
	}
}
