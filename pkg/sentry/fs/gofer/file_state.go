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

package gofer

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/fs"
)

// afterLoad is invoked by stateify.
func (f *fileOperations) afterLoad() {
	load := func() error {
		f.inodeOperations.fileState.waitForLoad()

		// Manually load the open handles.
		var err error
		// TODO(b/38173783): Context is not plumbed to save/restore.
		f.handles, err = f.inodeOperations.fileState.getHandles(context.Background(), f.flags)
		if err != nil {
			return fmt.Errorf("failed to re-open handle: %v", err)
		}
		return nil
	}
	fs.Async(fs.CatchError(load))
}
