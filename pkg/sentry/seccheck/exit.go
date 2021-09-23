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
)

// ExitNotifyParentInfo contains information used by the ExitNotifyParent
// checkpoint.
//
// +fieldenum ExitNotifyParent
type ExitNotifyParentInfo struct {
	// Exiter identifies the exiting thread. Note that by the checkpoint's
	// definition, Exiter.ThreadID == Exiter.ThreadGroupID and
	// Exiter.ThreadStartTime == Exiter.ThreadGroupStartTime, so requesting
	// ThreadGroup* fields is redundant.
	Exiter TaskInfo

	// ExitStatus is the exiting thread group's exit status, as reported
	// by wait*().
	ExitStatus linux.WaitStatus
}

// ExitNotifyParentReq returns fields required by the ExitNotifyParent
// checkpoint.
func (s *state) ExitNotifyParentReq() ExitNotifyParentFieldSet {
	return s.exitNotifyParentReq.Load()
}

// ExitNotifyParent is called at the ExitNotifyParent checkpoint.
//
// The ExitNotifyParent checkpoint occurs when a zombied thread group leader,
// not waiting for exit acknowledgement from a non-parent ptracer, becomes the
// last non-dead thread in its thread group and notifies its parent of its
// exiting.
func (s *state) ExitNotifyParent(ctx context.Context, mask ExitNotifyParentFieldSet, info *ExitNotifyParentInfo) error {
	for _, c := range s.getCheckers() {
		if err := c.ExitNotifyParent(ctx, mask, *info); err != nil {
			return err
		}
	}
	return nil
}
