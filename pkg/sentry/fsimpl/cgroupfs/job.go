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
	"bytes"
	"fmt"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/usermem"
)

// +stateify savable
type jobController struct {
	controllerCommon
	id int64
}

var _ controller = (*jobController)(nil)

func newJobController(fs *filesystem) *jobController {
	c := &jobController{}
	c.controllerCommon.init(controllerJob, fs)
	return c
}

func (c *jobController) AddControlFiles(ctx context.Context, creds *auth.Credentials, _ *cgroupInode, contents map[string]kernfs.Inode) {
	contents["job.id"] = c.fs.newControllerWritableFile(ctx, creds, &jobIDData{c: c})
}

// +stateify savable
type jobIDData struct {
	c *jobController
}

// Generate implements vfs.DynamicBytesSource.Generate.
func (d *jobIDData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	fmt.Fprintf(buf, "%d\n", d.c.id)
	return nil
}

// Write implements vfs.WritableDynamicBytesSource.Write.
func (d *jobIDData) Write(ctx context.Context, src usermem.IOSequence, offset int64) (int64, error) {
	val, n, err := parseInt64FromString(ctx, src, offset)
	if err != nil {
		return n, err
	}
	d.c.id = val
	return n, nil
}
