// Copyright 2023 The gVisor Authors.
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
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/usermem"
)

const (
	allowedDevices = "devices.allow"
	deniedDevices  = "devices.deny"
	wildcardDevice = 'a'
)

// permission represents a device access, read, write, and mknod.
type permission string

// +stateify savable
type deviceRule struct {
	// Device type, when the type is all, the following fields are ignored.
	controllerType rune
	// The device's major number.
	major *int64
	// The device's minor number.
	minor *int64
	// Cgroup access permission.
	access permission
}

// +stateify savable
type devicesController struct {
	controllerCommon
	controllerStateless
	controllerNoResource

	// mu protects the fields below.
	mu sync.Mutex `state:"nosave"`

	// Allow or deny the device rules below.
	allow       bool
	deviceRules []deviceRule
}

// +stateify savable
type allowedDevicesData struct {
	c *devicesController
}

// Generate implements vfs.DynamicBytesSource.Generate.
func (d *allowedDevicesData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	return generate(ctx, buf, d.c, true)
}

// Write implements vfs.WritableDynamicBytesSource.Write.
func (d *allowedDevicesData) Write(ctx context.Context, _ *vfs.FileDescription, src usermem.IOSequence, offset int64) (int64, error) {
	return write(ctx, src, offset, d.c, true)
}

// +stateify savable
type deniedDevicesData struct {
	c *devicesController
}

// Generate implements vfs.DynamicBytesSource.Generate.
func (d *deniedDevicesData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	return generate(ctx, buf, d.c, false)
}

// Write implements vfs.WritableDynamicBytesSource.Write.
func (d *deniedDevicesData) Write(ctx context.Context, _ *vfs.FileDescription, src usermem.IOSequence, offset int64) (int64, error) {
	return write(ctx, src, offset, d.c, true)
}

func generate(ctx context.Context, buf *bytes.Buffer, c *devicesController, allow bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if allow == c.allow && len(c.deviceRules) > 0 {
		for i, rule := range c.deviceRules {
			if rule.controllerType == wildcardDevice {
				buf.Reset()
				buf.WriteRune(wildcardDevice)
				return nil
			}
			buf.WriteString(deviceRuleString(rule))
			if i < len(c.deviceRules)-1 {
				buf.WriteRune(',')
			}
		}
	} else {
		buf.WriteString("")
	}
	return nil
}

func write(ctx context.Context, src usermem.IOSequence, offset int64, c *devicesController, allow bool) (int64, error) {
	// TODO(b/289099718): add functions to add and remove rules when writing to device controller data.
	return 0, nil
}

var _ controller = (*devicesController)(nil)

func newDevicesController(fs *filesystem) *devicesController {
	// The root device cgroup starts with rwm to all.
	c := &devicesController{
		allow:       true,
		deviceRules: []deviceRule{},
	}
	c.controllerCommon.init(kernel.CgroupControllerJob, fs)
	return c
}

// Clone implements controller.Clone.
func (c *devicesController) Clone() controller {
	c.mu.Lock()
	defer c.mu.Unlock()
	newRules := make([]deviceRule, len(c.deviceRules))
	copy(newRules, c.deviceRules)
	new := &devicesController{
		allow:       c.allow,
		deviceRules: newRules,
	}
	new.controllerCommon.cloneFromParent(c)
	return new
}

// AddControlFiles implements controller.AddControlFiles.
func (c *devicesController) AddControlFiles(ctx context.Context, creds *auth.Credentials, _ *cgroupInode, contents map[string]kernfs.Inode) {
	contents[allowedDevices] = c.fs.newControllerWritableFile(ctx, creds, &allowedDevicesData{c: c}, true)
	contents[deniedDevices] = c.fs.newControllerWritableFile(ctx, creds, &deniedDevicesData{c: c}, true)
}

func deviceRuleString(rule deviceRule) string {
	return fmt.Sprintf("%c %s:%s %s", rule.controllerType, deviceNumber(rule.major), deviceNumber(rule.minor), rule.access)
}

// deviceNumber converts a device number to string.
func deviceNumber(number *int64) string {
	if number == nil {
		return "*"
	}
	return fmt.Sprint(number)
}
