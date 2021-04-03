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

package specutils

import (
	"fmt"
	"math/bits"
	"path"
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
)

type mapping struct {
	set bool
	val uint32
}

// optionsMap maps mount propagation-related OCI filesystem options to mount(2)
// syscall flags.
var optionsMap = map[string]mapping{
	"acl":           {set: true, val: unix.MS_POSIXACL},
	"async":         {set: false, val: unix.MS_SYNCHRONOUS},
	"atime":         {set: false, val: unix.MS_NOATIME},
	"bind":          {set: true, val: unix.MS_BIND},
	"defaults":      {set: true, val: 0},
	"dev":           {set: false, val: unix.MS_NODEV},
	"diratime":      {set: false, val: unix.MS_NODIRATIME},
	"dirsync":       {set: true, val: unix.MS_DIRSYNC},
	"exec":          {set: false, val: unix.MS_NOEXEC},
	"noexec":        {set: true, val: unix.MS_NOEXEC},
	"iversion":      {set: true, val: unix.MS_I_VERSION},
	"loud":          {set: false, val: unix.MS_SILENT},
	"mand":          {set: true, val: unix.MS_MANDLOCK},
	"noacl":         {set: false, val: unix.MS_POSIXACL},
	"noatime":       {set: true, val: unix.MS_NOATIME},
	"nodev":         {set: true, val: unix.MS_NODEV},
	"nodiratime":    {set: true, val: unix.MS_NODIRATIME},
	"noiversion":    {set: false, val: unix.MS_I_VERSION},
	"nomand":        {set: false, val: unix.MS_MANDLOCK},
	"norelatime":    {set: false, val: unix.MS_RELATIME},
	"nostrictatime": {set: false, val: unix.MS_STRICTATIME},
	"nosuid":        {set: true, val: unix.MS_NOSUID},
	"rbind":         {set: true, val: unix.MS_BIND | unix.MS_REC},
	"relatime":      {set: true, val: unix.MS_RELATIME},
	"remount":       {set: true, val: unix.MS_REMOUNT},
	"ro":            {set: true, val: unix.MS_RDONLY},
	"rw":            {set: false, val: unix.MS_RDONLY},
	"silent":        {set: true, val: unix.MS_SILENT},
	"strictatime":   {set: true, val: unix.MS_STRICTATIME},
	"suid":          {set: false, val: unix.MS_NOSUID},
	"sync":          {set: true, val: unix.MS_SYNCHRONOUS},
}

// verityMountOptions is the set of valid verity mount option keys.
var verityMountOptions = map[string]struct{}{
	"verity.roothash": struct{}{},
	"verity.action":   struct{}{},
}

// propOptionsMap is similar to optionsMap, but it lists propagation options
// that cannot be used together with other flags.
var propOptionsMap = map[string]mapping{
	"private":     {set: true, val: unix.MS_PRIVATE},
	"rprivate":    {set: true, val: unix.MS_PRIVATE | unix.MS_REC},
	"slave":       {set: true, val: unix.MS_SLAVE},
	"rslave":      {set: true, val: unix.MS_SLAVE | unix.MS_REC},
	"unbindable":  {set: true, val: unix.MS_UNBINDABLE},
	"runbindable": {set: true, val: unix.MS_UNBINDABLE | unix.MS_REC},
}

// invalidOptions list options not allowed.
//   - shared: sandbox must be isolated from the host. Propagating mount changes
//     from the sandbox to the host breaks the isolation.
var invalidOptions = []string{"shared", "rshared"}

// OptionsToFlags converts mount options to syscall flags.
func OptionsToFlags(opts []string) uint32 {
	return optionsToFlags(opts, optionsMap)
}

// PropOptionsToFlags converts propagation mount options to syscall flags.
// Propagation options cannot be set other with other options and must be
// handled separately.
func PropOptionsToFlags(opts []string) uint32 {
	return optionsToFlags(opts, propOptionsMap)
}

func optionsToFlags(opts []string, source map[string]mapping) uint32 {
	var rv uint32
	for _, opt := range opts {
		if m, ok := source[opt]; ok {
			if m.set {
				rv |= m.val
			} else {
				rv ^= m.val
			}
		}
	}
	return rv
}

// validateMount validates that spec mounts are correct.
func validateMount(mnt *specs.Mount) error {
	if !path.IsAbs(mnt.Destination) {
		return fmt.Errorf("Mount.Destination must be an absolute path: %v", mnt)
	}
	if mnt.Type == "bind" {
		return ValidateMountOptions(mnt.Options)
	}
	return nil
}

func moptKey(opt string) string {
	if len(opt) == 0 {
		return opt
	}
	// Guaranteed to have at least one token, since opt is not empty.
	return strings.SplitN(opt, "=", 2)[0]
}

// ValidateMountOptions validates that mount options are correct.
func ValidateMountOptions(opts []string) error {
	for _, o := range opts {
		if ContainsStr(invalidOptions, o) {
			return fmt.Errorf("mount option %q is not supported", o)
		}
		_, ok1 := optionsMap[o]
		_, ok2 := propOptionsMap[o]
		_, ok3 := verityMountOptions[moptKey(o)]
		if !ok1 && !ok2 && !ok3 {
			return fmt.Errorf("unknown mount option %q", o)
		}
		if err := validatePropagation(o); err != nil {
			return err
		}
	}
	return nil
}

// ValidateRootfsPropagation validates that rootfs propagation options are
// correct.
func validateRootfsPropagation(opt string) error {
	flags := PropOptionsToFlags([]string{opt})
	if flags&(unix.MS_SLAVE|unix.MS_PRIVATE) == 0 {
		return fmt.Errorf("root mount propagation option must specify private or slave: %q", opt)
	}
	return validatePropagation(opt)
}

func validatePropagation(opt string) error {
	flags := PropOptionsToFlags([]string{opt})
	exclusive := flags & (unix.MS_SLAVE | unix.MS_PRIVATE | unix.MS_SHARED | unix.MS_UNBINDABLE)
	if bits.OnesCount32(exclusive) > 1 {
		return fmt.Errorf("mount propagation options are mutually exclusive: %q", opt)
	}
	return nil
}
