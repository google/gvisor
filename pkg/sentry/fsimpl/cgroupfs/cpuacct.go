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

package cgroupfs

import (
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

// +stateify savable
type cpuacctController struct {
	controllerCommon
}

var _ controller = (*cpuacctController)(nil)

func newCPUAcctController(fs *filesystem) *cpuacctController {
	c := &cpuacctController{}
	c.controllerCommon.init(controllerCPUAcct, fs)
	return c
}

// AddControlFiles implements controller.AddControlFiles.
func (c *cpuacctController) AddControlFiles(ctx context.Context, creds *auth.Credentials, _ *cgroupInode, contents map[string]kernfs.Inode) {
	// This controller is currently intentionally empty.
}
