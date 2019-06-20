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

// Package unimpl contains interface to emit events about unimplemented
// features.
package unimpl

import (
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/context"
)

// contextID is the events package's type for context.Context.Value keys.
type contextID int

const (
	// CtxEvents is a Context.Value key for a Events.
	CtxEvents contextID = iota
)

// Events interface defines method to emit unsupported events.
type Events interface {
	EmitUnimplementedEvent(context.Context)
}

// EmitUnimplementedEvent emits unsupported syscall event to the context.
func EmitUnimplementedEvent(ctx context.Context) {
	e := ctx.Value(CtxEvents)
	if e == nil {
		log.Warningf("Context.Value(CtxEvents) not present, unimplemented syscall event not reported.")
		return
	}
	e.(Events).EmitUnimplementedEvent(ctx)
}
