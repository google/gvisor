// Copyright 2018 Google Inc.
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
	"sync/atomic"
	"testing"
	"time"

	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/auth"
	ktime "gvisor.googlesource.com/gvisor/pkg/sentry/kernel/time"
	"gvisor.googlesource.com/gvisor/pkg/sentry/limits"
	"gvisor.googlesource.com/gvisor/pkg/sentry/platform"
	"gvisor.googlesource.com/gvisor/pkg/sentry/platform/ptrace"
	"gvisor.googlesource.com/gvisor/pkg/sentry/uniqueid"
)

// Context returns a Context that may be used in tests. Uses ptrace as the
// platform.Platform.
func Context(tb testing.TB) context.Context {
	p, err := ptrace.New()
	if err != nil {
		tb.Fatal(err)
	}
	// Test usage of context.Background is fine.
	return &testContext{
		Context:  context.Background(),
		l:        limits.NewLimitSet(),
		platform: p,
	}
}

type testContext struct {
	context.Context
	l        *limits.LimitSet
	platform platform.Platform
}

// globalUniqueID tracks incremental unique identifiers for tests.
var globalUniqueID uint64

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

// Value implements context.Context.
func (t *testContext) Value(key interface{}) interface{} {
	switch key {
	case limits.CtxLimits:
		return t.l
	case platform.CtxPlatform:
		return t.platform
	case uniqueid.CtxGlobalUniqueID:
		return atomic.AddUint64(&globalUniqueID, 1)
	case uniqueid.CtxInotifyCookie:
		return atomic.AddUint32(&lastInotifyCookie, 1)
	case ktime.CtxRealtimeClock:
		return hostClock{}
	default:
		return t.Context.Value(key)
	}
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
