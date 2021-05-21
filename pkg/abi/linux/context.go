// Copyright 2021 The gVisor Authors.
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

package linux

import (
	"gvisor.dev/gvisor/pkg/context"
)

// contextID is the linux package's type for context.Context.Value keys.
type contextID int

const (
	// CtxSignalNoInfoFunc is a Context.Value key for a function to send signals.
	CtxSignalNoInfoFunc contextID = iota
)

// SignalNoInfoFuncFromContext returns a callback function that can be used to send a
// signal to the given context.
func SignalNoInfoFuncFromContext(ctx context.Context) func(Signal) error {
	if f := ctx.Value(CtxSignalNoInfoFunc); f != nil {
		return f.(func(Signal) error)
	}
	return nil
}
