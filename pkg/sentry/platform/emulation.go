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

package platform

import "gvisor.dev/gvisor/pkg/context"

// taskWrapper wraps a context.Context.
type taskWrapper struct {
	context.Context
}

// emulationContext is used for emulation.
//
// It wraps an existing context but prioritizes resolution via context.NoTask,
// since the task state should not be modified during emulation. However, we
// allow logging and other operations to be directed to the correct task.
type emulationContext struct {
	taskWrapper
	context.NoTask
}
