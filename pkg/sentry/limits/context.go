// Copyright 2018 Google LLC
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

package limits

import (
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
)

// contextID is the limit package's type for context.Context.Value keys.
type contextID int

const (
	// CtxLimits is a Context.Value key for a LimitSet.
	CtxLimits contextID = iota
)

// FromContext returns the limits that apply to ctx.
func FromContext(ctx context.Context) *LimitSet {
	if v := ctx.Value(CtxLimits); v != nil {
		return v.(*LimitSet)
	}
	return nil
}
