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

package time

import (
	"gvisor.dev/gvisor/pkg/sentry/context"
)

// contextID is the time package's type for context.Context.Value keys.
type contextID int

const (
	// CtxRealtimeClock is a Context.Value key for the current real time.
	CtxRealtimeClock contextID = iota
)

// RealtimeClockFromContext returns the real time clock associated with context
// ctx.
func RealtimeClockFromContext(ctx context.Context) Clock {
	if v := ctx.Value(CtxRealtimeClock); v != nil {
		return v.(Clock)
	}
	return nil
}

// NowFromContext returns the current real time associated with context ctx.
func NowFromContext(ctx context.Context) Time {
	if clk := RealtimeClockFromContext(ctx); clk != nil {
		return clk.Now()
	}
	panic("encountered context without RealtimeClock")
}
