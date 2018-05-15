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

package inet

import (
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
)

// contextID is the inet package's type for context.Context.Value keys.
type contextID int

const (
	// CtxStack is a Context.Value key for a network stack.
	CtxStack contextID = iota
)

// StackFromContext returns the network stack associated with ctx.
func StackFromContext(ctx context.Context) Stack {
	if v := ctx.Value(CtxStack); v != nil {
		return v.(Stack)
	}
	return nil
}
