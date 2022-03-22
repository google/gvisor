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
	"gvisor.dev/gvisor/pkg/context"
	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
)

// ExitNotifyParent is called at the ExitNotifyParent checkpoint.
//
// The ExitNotifyParent checkpoint occurs when a zombied thread group leader,
// not waiting for exit acknowledgement from a non-parent ptracer, becomes the
// last non-dead thread in its thread group and notifies its parent of its
// exiting.
func (s *State) ExitNotifyParent(ctx context.Context, fields FieldSet, info *pb.ExitNotifyParentInfo) error {
	for _, c := range s.getCheckers() {
		if err := c.ExitNotifyParent(ctx, fields, info); err != nil {
			return err
		}
	}
	return nil
}
