// Copyright 2022 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cgroup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	systemdDbus "github.com/coreos/go-systemd/v22/dbus"
	dbus "github.com/godbus/dbus/v5"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/log"
)

var (
	// ErrBadResourceSpec indicates that a cgroupSystemd function was
	// passed a specs.LinuxResources object that is impossible or illegal
	// to process.
	ErrBadResourceSpec = errors.New("misconfigured resource spec")
	// ErrInvalidSlice indicates that the slice name passed via cgroup.Path is
	// invalid.
	ErrInvalidSlice = errors.New("invalid slice name")
)

// cgroupSystemd represents a cgroupv2 managed by systemd.
type cgroupSystemd struct {
	cgroupV2
	// Name is the name of the of the systemd scope that controls the cgroups.
	Name string
	// Parent is the encapsulating slice.
	Parent string
	// ScopePrefix is the prefix for the scope name.
	ScopePrefix string

	properties []systemdDbus.Property
	dbusConn   *systemdDbus.Conn
}

func newCgroupV2Systemd(cgv2 *cgroupV2) (*cgroupSystemd, error) {
	if !isRunningSystemd() {
		return nil, fmt.Errorf("systemd not running on host")
	}
	ctx := context.Background()
	cg := &cgroupSystemd{cgroupV2: *cgv2}
	// Parse the path from expected "slice:prefix:name"
	// for e.g. "system.slice:docker:1234"
	parts := strings.Split(cg.Path, ":")
	if len(parts) != 3 {
		return nil, fmt.Errorf("expected cgroupsPath to be of format \"slice:prefix:name\" for systemd cgroups, got %q instead", cg.Path)
	}
	cg.Parent = parts[0]
	cg.ScopePrefix = parts[1]
	cg.Name = parts[2]
	if err := validSlice(cg.Parent); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidGroupPath, err)
	}
	// Rewrite Path so that it is compatible with cgroupv2 methods.
	cg.Path = filepath.Join(expandSlice(cg.Parent), cg.unitName())
	conn, err := systemdDbus.NewWithContext(ctx)
	if err != nil {
		return nil, err
	}
	var version int
	if version, err = systemdVersion(conn); err != nil {
		return nil, fmt.Errorf("error parsing systemd version: %v", err)
	}
	if version < 244 {
		return nil, fmt.Errorf("systemd version %d not supported, please upgrade to at least 244", version)
	}
	cg.dbusConn = conn
	return cg, err
}

// Install configures the properties for a scope unit but does not start the
// unit.
func (c *cgroupSystemd) Install(res *specs.LinuxResources) error {
	log.Debugf("Installing systemd cgroup resource controller under %v", c.Parent)
	c.properties = append(c.properties, systemdDbus.PropSlice(c.Parent))
	c.properties = append(c.properties, systemdDbus.PropDescription("Secure container "+c.Name))
	pid := os.Getpid()
	c.properties = append(c.properties, systemdDbus.PropPids(uint32(pid)))
	// We always want proper accounting for the container for reporting resource
	// usage.
	c.addProp("MemoryAccounting", true)
	c.addProp("CPUAccounting", true)
	c.addProp("TasksAccounting", true)
	c.addProp("IOAccounting", true)
	// Delegate must be true so that the container can manage its own cgroups.
	c.addProp("Delegate", true)
	// For compatibility with runc.
	c.addProp("DefaultDependencies", false)

	for controllerName, ctrlr := range controllers2 {
		// First check if our controller is found in the system.
		found := false
		for _, knownController := range c.Controllers {
			if controllerName == knownController {
				found = true
			}
		}
		if found {
			props, err := ctrlr.generateProperties(res)
			if err != nil {
				return err
			}
			c.properties = append(c.properties, props...)
			continue
		}
		if ctrlr.optional() {
			if err := ctrlr.skip(res); err != nil {
				return err
			}
		} else {
			return fmt.Errorf("mandatory cgroup controller %q is missing for %q", controllerName, c.Path)
		}
	}
	return nil
}

func (c *cgroupSystemd) unitName() string {
	return fmt.Sprintf("%s-%s.scope", c.ScopePrefix, c.Name)
}

// MakePath builds a path to the given controller.
func (c *cgroupSystemd) MakePath(string) string {
	fullSlicePath := expandSlice(c.Parent)
	path := filepath.Join(c.Mountpoint, fullSlicePath, c.unitName())
	return path
}

// Join implements Cgroup.Join.
func (c *cgroupSystemd) Join() (func(), error) {
	log.Debugf("Joining systemd cgroup %v", c.unitName())
	timeout := 30 * time.Second
	ctx := context.Background()
	// Clean up partially created cgroups on error. Errors during cleanup itself
	// are ignored.
	clean := cleanup.Make(func() { _ = c.Uninstall() })
	defer clean.Clean()

	conn, err := systemdDbus.NewWithContext(ctx)
	if err != nil {
		return nil, err
	}
	c.dbusConn = conn
	unitName := c.unitName()
	statusChan := make(chan string)
	timedCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if _, err := c.dbusConn.StartTransientUnitContext(timedCtx, unitName, "replace", c.properties, statusChan); err == nil {
		s := <-statusChan
		close(statusChan)
		switch s {
		case "done":
		// All cases that are not "done" according to the dbus package.
		case "cancelled", "timeout", "failed", "dependency", "skipped":
			c.dbusConn.ResetFailedUnitContext(ctx, unitName)
			return nil, fmt.Errorf("error creating systemd unit `%s`: got %s", unitName, s)
		default:
			c.dbusConn.ResetFailedUnitContext(ctx, unitName)
			return nil, fmt.Errorf("unknown job completion status %q", s)
		}
	} else if unitAlreadyExists(err) {
		return clean.Release(), nil
	} else {
		return nil, fmt.Errorf("systemd error: %v", err)
	}
	if _, err = c.createCgroupPaths(); err != nil {
		return nil, err
	}
	return clean.Release(), nil
}

// unitAlreadyExists returns true if the error is that a systemd unit already
// exists.
func unitAlreadyExists(err error) bool {
	if err != nil {
		var derr dbus.Error
		if errors.As(err, &derr) {
			return strings.Contains(derr.Name, "org.freedesktop.systemd1.UnitExists")
		}
	}
	return false
}

// systemd represents slice hierarchy using `-`, so we need to follow suit when
// generating the path of slice. Essentially, test-a-b.slice becomes
// /test.slice/test-a.slice/test-a-b.slice.
func expandSlice(slice string) string {
	var path, prefix string
	suffix := ".slice"
	sliceName := strings.TrimSuffix(slice, suffix)
	// If input was -.slice, we should just return root now.
	if sliceName == "-" {
		return "/"
	}
	for _, component := range strings.Split(sliceName, "-") {
		// Append the component to the path and to the prefix.
		path += "/" + prefix + component + suffix
		prefix += component + "-"
	}
	return path
}

func validSlice(slice string) error {
	suffix := ".slice"
	// Name has to end with ".slice", but can't be just ".slice".
	if slice == suffix || !strings.HasSuffix(slice, suffix) {
		return fmt.Errorf("%w: %s", ErrInvalidSlice, slice)
	}

	// Path-separators are not allowed.
	if strings.Contains(slice, "/") {
		return fmt.Errorf("%w: %s", ErrInvalidSlice, slice)
	}

	sliceName := strings.TrimSuffix(slice, suffix)
	// If input was -.slice, we should just return root now.
	if sliceName == "-" {
		return nil
	}
	for _, component := range strings.Split(sliceName, "-") {
		// test--a.slice isn't permitted, nor is -test.slice.
		if component == "" {
			return fmt.Errorf("%w: %s", ErrInvalidSlice, slice)
		}
	}
	return nil
}

var systemdCheck struct {
	once  sync.Once
	cache bool
}

func isRunningSystemd() bool {
	systemdCheck.once.Do(func() {
		fi, err := os.Lstat("/run/systemd/system")
		systemdCheck.cache = err == nil && fi.IsDir()
	})
	return systemdCheck.cache
}

func systemdVersion(conn *systemdDbus.Conn) (int, error) {
	vStr, err := conn.GetManagerProperty("Version")
	if err != nil {
		return -1, errors.New("unable to get systemd version")
	}
	// vStr should be of the form:
	// "v245.4-1.fc32", "245", "v245-1.fc32", "245-1.fc32" (without quotes).
	// The result for all of the above should be 245.
	// Thus, we unconditionally remove the "v" prefix
	// and then match on the first integer we can grab.
	re := regexp.MustCompile(`v?([0-9]+)`)
	matches := re.FindStringSubmatch(vStr)
	if len(matches) < 2 {
		return -1, fmt.Errorf("can't parse version %q: incorrect number of matches %d", vStr, len(matches))
	}
	version, err := strconv.Atoi(matches[1])
	if err != nil {
		return -1, fmt.Errorf("%w: can't parse version %q", err, vStr)
	}
	return version, nil
}

func addIOProps(props []systemdDbus.Property, name string, devs []specs.LinuxThrottleDevice) []systemdDbus.Property {
	for _, dev := range devs {
		val := fmt.Sprintf("%d:%d %d", dev.Major, dev.Minor, dev.Rate)
		props = append(props, newProp(name, val))
	}
	return props
}

func (c *cgroupSystemd) addProp(name string, value any) {
	if value == nil {
		return
	}
	c.properties = append(c.properties, newProp(name, value))
}

func newProp(name string, units any) systemdDbus.Property {
	return systemdDbus.Property{
		Name:  name,
		Value: dbus.MakeVariant(units),
	}
}

// CreateMockSystemdCgroup returns a mock Cgroup configured for systemd. This
// is useful for testing.
func CreateMockSystemdCgroup() Cgroup {
	return &cgroupSystemd{
		Name:        "test",
		ScopePrefix: "runsc",
		Parent:      "system.slice",
		cgroupV2: cgroupV2{
			Mountpoint: "/sys/fs/cgroup",
			Path:       "/a/random/path",
		},
	}
}
