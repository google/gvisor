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
	"strconv"
	"strings"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/usermem"
)

const (
	canRead = 1 << iota
	canWrite
	canMknod
)
const (
	allowedDevices       = "devices.allow"
	controlledDevices    = "devices.list"
	deniedDevices        = "devices.deny"
	wildcardDeviceNumber = -1
)
const (
	blockDevice    deviceType = "b"
	charDevice     deviceType = "c"
	wildcardDevice deviceType = "a"
)

// type denotes a device's type.
type deviceType string

func (d deviceType) valid() bool {
	switch d {
	case wildcardDevice, charDevice, blockDevice:
		return true
	default:
		return false
	}
}

// permission represents a device access, read, write, and mknod.
type permission string

func (p permission) valid() bool {
	for _, c := range p {
		switch c {
		case 'r', 'w', 'm':
			continue
		default:
			return false
		}
	}
	return true
}

// toBinary converts permission to its binary representation.
func (p permission) toBinary() int {
	var perm int
	for _, c := range p {
		switch c {
		case 'r':
			perm |= canRead
		case 'w':
			perm |= canWrite
		case 'm':
			perm |= canMknod
		}
	}
	return perm
}

// union returns a permission which unions p and perm.
func (p permission) union(perm permission) permission {
	return fromBinary(p.toBinary() | perm.toBinary())
}

// difference returns a permission which consists of accesses in p and not in perm.
func (p permission) difference(perm permission) permission {
	return fromBinary(p.toBinary() & ^perm.toBinary())
}

// fromBinary converts permission to its string representation.
func fromBinary(i int) permission {
	var perm permission
	if i&canRead == canRead {
		perm += "r"
	}
	if i&canWrite == canWrite {
		perm += "w"
	}
	if i&canMknod == canMknod {
		perm += "m"
	}
	return perm
}

// +stateify savable
type deviceID struct {
	// Device type, when the type is all, the following fields are ignored.
	controllerType deviceType
	// The device's major number.
	major int64
	// The device's minor number.
	minor int64
}

// +stateify savable
type devicesController struct {
	controllerCommon
	controllerStateless
	controllerNoResource

	// mu protects the fields below.
	mu sync.Mutex `state:"nosave"`

	// Allow or deny the device rules below.
	defaultAllow bool
	deviceRules  map[deviceID]permission
}

// +stateify savable
type allowedDevicesData struct {
	c *devicesController
}

// Generate implements vfs.DynamicBytesSource.Generate. The devices.allow shows nothing.
func (d *allowedDevicesData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	return nil
}

// Write implements vfs.WritableDynamicBytesSource.Write.
func (d *allowedDevicesData) Write(ctx context.Context, _ *vfs.FileDescription, src usermem.IOSequence, offset int64) (int64, error) {
	return d.c.write(ctx, src, offset, true)
}

// +stateify savable
type deniedDevicesData struct {
	c *devicesController
}

// Generate implements vfs.DynamicBytesSource.Generate. The devices.deny shows nothing.
func (d *deniedDevicesData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	return nil
}

// Write implements vfs.WritableDynamicBytesSource.Write.
func (d *deniedDevicesData) Write(ctx context.Context, _ *vfs.FileDescription, src usermem.IOSequence, offset int64) (int64, error) {
	return d.c.write(ctx, src, offset, false)
}

// +stateify savable
type controlledDevicesData struct {
	c *devicesController
}

// Generate implements vfs.DynamicBytesSource.Generate.
//
// The corresponding devices.list shows devices for which access control is set.
func (d *controlledDevicesData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	return d.c.generate(ctx, buf)
}

func (c *devicesController) addRule(id deviceID, newPermission permission) error {
	existingPermission := c.deviceRules[id]
	c.deviceRules[id] = existingPermission.union(newPermission)
	return nil
}

func (c *devicesController) removeRule(id deviceID, p permission) error {
	// cgroupv1 ignores silently requests to remove a partially-matching wildcard rule,
	// which are {majorDevice:wildcardDevice}, {wildcardDevice:minorDevice}, and {wildcardDevice:wildcardDevice}
	for _, wildcardDeviceID := range []deviceID{
		{controllerType: id.controllerType, major: id.major, minor: wildcardDeviceNumber},
		{controllerType: id.controllerType, major: wildcardDeviceNumber, minor: id.minor},
		{controllerType: id.controllerType, major: wildcardDeviceNumber, minor: wildcardDeviceNumber},
	} {
		// If there is a exact match, the permission needs to be updated.
		if id == wildcardDeviceID {
			continue
		}
		if _, exist := c.deviceRules[wildcardDeviceID]; exist {
			return nil
		}
	}
	if existingPermission, exist := c.deviceRules[id]; exist {
		if newPermission := existingPermission.difference(p); len(newPermission) == 0 {
			delete(c.deviceRules, id)
		} else {
			c.deviceRules[id] = newPermission
		}
	}
	return nil
}

func (c *devicesController) applyRule(id deviceID, p permission, allow bool) error {
	if !id.controllerType.valid() {
		return linuxerr.EINVAL
	}
	// If the device type is all, it will reset the rules for all.
	if id.controllerType == wildcardDevice {
		c.defaultAllow = allow
		clear(c.deviceRules)
		return nil
	}
	if !p.valid() {
		return linuxerr.EINVAL
	}
	if len(c.deviceRules) == 0 {
		c.defaultAllow = allow
		clear(c.deviceRules)
	}
	if allow == c.defaultAllow {
		return c.addRule(id, p)
	}
	return c.removeRule(id, p)
}

func (c *devicesController) generate(ctx context.Context, buf *bytes.Buffer) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case c.defaultAllow && len(c.deviceRules) > 0:
		for id, p := range c.deviceRules {
			buf.WriteString(deviceRuleString(id, p))
			// It lists one rule per line.
			buf.WriteRune('\n')
		}
	case c.defaultAllow && len(c.deviceRules) == 0:
		buf.WriteString(deviceRuleString(deviceID{controllerType: wildcardDevice, major: wildcardDeviceNumber, minor: wildcardDeviceNumber}, "rwm"))
	case !c.defaultAllow && len(c.deviceRules) == 0:
		buf.WriteString("")
	default:
		// When allow-all rule presents at devices.list, it actually indicates that
		// the cgroup is in black-list mode.
		buf.WriteString(deviceRuleString(deviceID{controllerType: wildcardDevice, major: wildcardDeviceNumber, minor: wildcardDeviceNumber}, "rwm"))
	}
	return nil
}

func (c *devicesController) write(ctx context.Context, src usermem.IOSequence, offset int64, allow bool) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if src.NumBytes() > hostarch.PageSize {
		return 0, linuxerr.EINVAL
	}
	buf := copyScratchBufferFromContext(ctx, hostarch.PageSize)
	n, err := src.CopyIn(ctx, buf)
	if err != nil {
		return 0, err
	}
	rule := string(buf[:n])
	fields := strings.FieldsFunc(rule, func(r rune) bool {
		return r == ' ' || r == ':'
	})
	switch {
	case len(fields) != 1 && len(fields) != 4:
		return 0, linuxerr.EINVAL
	case len(fields) == 4:
		controllerType := deviceType(fields[0])
		perm := permission(fields[3])
		if i := strings.IndexFunc(fields[3], func(r rune) bool { return r == '\n' }); i != -1 {
			perm = perm[:i]
		}
		if len(perm) > 3 {
			perm = perm[:3]
		}
		majorDevice, err := toDeviceNumber(fields[1])
		if err != nil {
			return 0, err
		}
		minorDevice, err := toDeviceNumber(fields[2])
		if err != nil {
			return 0, err
		}
		id := deviceID{
			controllerType: controllerType,
			major:          majorDevice,
			minor:          minorDevice,
		}
		if err := c.applyRule(id, perm, allow); err != nil {
			return 0, err
		}
	case len(fields) == 1:
		if deviceType(fields[0]) != wildcardDevice {
			return 0, linuxerr.EINVAL
		}
		if err := c.applyRule(deviceID{controllerType: wildcardDevice}, permission(""), allow); err != nil {
			return 0, err
		}
	}
	return int64(n), nil
}

var _ controller = (*devicesController)(nil)

func newDevicesController(fs *filesystem) *devicesController {
	// The root device cgroup starts with rwm to all.
	c := &devicesController{
		defaultAllow: true,
		deviceRules:  make(map[deviceID]permission),
	}
	c.controllerCommon.init(kernel.CgroupControllerDevices, fs)
	return c
}

// Clone implements controller.Clone.
func (c *devicesController) Clone() controller {
	c.mu.Lock()
	defer c.mu.Unlock()
	newRules := make(map[deviceID]permission)
	for id, p := range c.deviceRules {
		newRules[id] = p
	}
	new := &devicesController{
		defaultAllow: c.defaultAllow,
		deviceRules:  newRules,
	}
	new.controllerCommon.cloneFromParent(c)
	return new
}

// AddControlFiles implements controller.AddControlFiles.
func (c *devicesController) AddControlFiles(ctx context.Context, creds *auth.Credentials, _ *cgroupInode, contents map[string]kernfs.Inode) {
	contents[allowedDevices] = c.fs.newControllerWritableFile(ctx, creds, &allowedDevicesData{c: c}, true)
	contents[deniedDevices] = c.fs.newControllerWritableFile(ctx, creds, &deniedDevicesData{c: c}, true)
	contents[controlledDevices] = c.fs.newControllerFile(ctx, creds, &controlledDevicesData{c: c}, true)
}

func deviceRuleString(id deviceID, p permission) string {
	return fmt.Sprintf("%s %s:%s %s", id.controllerType, deviceNumber(id.major), deviceNumber(id.minor), p)
}

// deviceNumber converts a device number to string.
func deviceNumber(number int64) string {
	if number == wildcardDeviceNumber {
		return "*"
	}
	return fmt.Sprint(number)
}

func toDeviceNumber(s string) (int64, error) {
	if s == "*" {
		return wildcardDeviceNumber, nil
	}
	val, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, linuxerr.EINVAL
	}
	return val, nil
}
