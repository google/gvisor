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

// Package uniqueid defines context.Context keys for obtaining system-wide
// unique identifiers.
package uniqueid

import (
	"gvisor.dev/gvisor/pkg/context"
)

// contextID is the kernel package's type for context.Context.Value keys.
type contextID int

const (
	// CtxGlobalUniqueID is a Context.Value key for a system-wide
	// unique identifier.
	CtxGlobalUniqueID contextID = iota

	// CtxGlobalUniqueIDProvider is a Context.Value key for a
	// system-wide unique identifier generator.
	CtxGlobalUniqueIDProvider

	// CtxInotifyCookie is a Context.Value key for a unique inotify
	// event cookie.
	CtxInotifyCookie
)

// Provider generates a sequence of unique identifiers useful for,
// among other things, lock ordering.
type Provider interface {
	// UniqueID returns a new unique identifier.
	UniqueID() uint64
}

// GlobalFromContext returns a system-wide unique identifier from ctx.
func GlobalFromContext(ctx context.Context) uint64 {
	return ctx.Value(CtxGlobalUniqueID).(uint64)
}

// GlobalProviderFromContext returns a system-wide unique identifier from ctx.
func GlobalProviderFromContext(ctx context.Context) Provider {
	return ctx.Value(CtxGlobalUniqueIDProvider).(Provider)
}

// InotifyCookie generates a unique inotify event cookie from ctx.
func InotifyCookie(ctx context.Context) uint32 {
	return ctx.Value(CtxInotifyCookie).(uint32)
}
