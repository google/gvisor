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

package seccheck

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
)

// CloneInfo contains information used by the Clone checkpoint.
type CloneInfo struct {
	// ThreadID is the invoking thread's ID in the root PID namespace.
	ThreadID int32

	// ThreadGroupID is the invoking thread's group leader's ID in the root PID
	// namespace.
	ThreadGroupID int32

	// ThreadGroupStartTime is the invoking thread's group leader's
	// CLOCK_REALTIME start time.
	ThreadGroupStartTime ktime.Time

	// Args contains the arguments to kernel.Task.Clone().
	Args linux.CloneArgs

	// Credentials are the invoking thread's credentials.
	Credentials *auth.Credentials

	// NewThreadID is the created thread's ID in the root PID namespace.
	NewThreadID int32

	// NewThreadGroupID is the created thread's group leader's ID in the root
	// PID namespace.
	NewThreadGroupID int32

	// NewStartTime is the created thread's CLOCK_REALTIME start time.
	NewStartTime ktime.Time
}

// CloneFieldX represents CloneInfo field X.
const (
	CloneFieldThreadID CloneField = iota
	CloneFieldThreadGroupID
	CloneFieldThreadGroupStartTime
	CloneFieldArgs
	CloneFieldCredentials
	CloneFieldNewThreadID
	CloneFieldNewThreadGroupID
	CloneFieldNewStartTime

	cloneFieldMaxPlusOne
)

// CloneReq returns fields required by the Clone checkpoint.
func CloneReq() CloneFieldSet {
	return global.cloneReq.atomicLoad()
}

// Clone is called at the Clone checkpoint.
func Clone(ctx context.Context, mask CloneFieldSet, info *CloneInfo) error {
	for _, c := range getCheckers() {
		if err := c.Clone(ctx, mask, *info); err != nil {
			return err
		}
	}
	return nil
}
