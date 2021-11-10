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
)

// CloneInfo contains information used by the Clone checkpoint.
//
// +fieldenum Clone
type CloneInfo struct {
	// Invoker identifies the invoking thread.
	Invoker TaskInfo

	// Credentials are the invoking thread's credentials.
	Credentials *auth.Credentials

	// Args contains the arguments to kernel.Task.Clone().
	Args linux.CloneArgs

	// Created identifies the created thread.
	Created TaskInfo
}

// CloneReq returns fields required by the Clone checkpoint.
func (s *State) CloneReq() CloneFieldSet {
	return s.cloneReq.Load()
}

// Clone is called at the Clone checkpoint.
func (s *State) Clone(ctx context.Context, mask CloneFieldSet, info *CloneInfo) error {
	for _, c := range s.getCheckers() {
		if err := c.Clone(ctx, mask, *info); err != nil {
			return err
		}
	}
	return nil
}
