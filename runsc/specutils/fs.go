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
	"path"
	"syscall"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

type mapping struct {
	set bool
	val uint32
}

// optionsMap maps mount propagation-related OCI filesystem options to mount(2)
// syscall flags.
var optionsMap = map[string]mapping{
	"acl":           {set: true, val: syscall.MS_POSIXACL},
	"async":         {set: false, val: syscall.MS_SYNCHRONOUS},
	"atime":         {set: false, val: syscall.MS_NOATIME},
	"bind":          {set: true, val: syscall.MS_BIND},
	"defaults":      {set: true, val: 0},
	"dev":           {set: false, val: syscall.MS_NODEV},
	"diratime":      {set: false, val: syscall.MS_NODIRATIME},
	"dirsync":       {set: true, val: syscall.MS_DIRSYNC},
	"exec":          {set: false, val: syscall.MS_NOEXEC},
	"noexec":        {set: true, val: syscall.MS_NOEXEC},
	"iversion":      {set: true, val: syscall.MS_I_VERSION},
	"loud":          {set: false, val: syscall.MS_SILENT},
	"mand":          {set: true, val: syscall.MS_MANDLOCK},
	"noacl":         {set: false, val: syscall.MS_POSIXACL},
	"noatime":       {set: true, val: syscall.MS_NOATIME},
	"nodev":         {set: true, val: syscall.MS_NODEV},
	"nodiratime":    {set: true, val: syscall.MS_NODIRATIME},
	"noiversion":    {set: false, val: syscall.MS_I_VERSION},
	"nomand":        {set: false, val: syscall.MS_MANDLOCK},
	"norelatime":    {set: false, val: syscall.MS_RELATIME},
	"nostrictatime": {set: false, val: syscall.MS_STRICTATIME},
	"nosuid":        {set: true, val: syscall.MS_NOSUID},
	"rbind":         {set: true, val: syscall.MS_BIND | syscall.MS_REC},
	"relatime":      {set: true, val: syscall.MS_RELATIME},
	"remount":       {set: true, val: syscall.MS_REMOUNT},
	"ro":            {set: true, val: syscall.MS_RDONLY},
	"rw":            {set: false, val: syscall.MS_RDONLY},
	"silent":        {set: true, val: syscall.MS_SILENT},
	"strictatime":   {set: true, val: syscall.MS_STRICTATIME},
	"suid":          {set: false, val: syscall.MS_NOSUID},
	"sync":          {set: true, val: syscall.MS_SYNCHRONOUS},
}

// propOptionsMap is similar to optionsMap, but it lists propagation options
// that cannot be used together with other flags.
var propOptionsMap = map[string]mapping{
	"private":     {set: true, val: syscall.MS_PRIVATE},
	"rprivate":    {set: true, val: syscall.MS_PRIVATE | syscall.MS_REC},
	"slave":       {set: true, val: syscall.MS_SLAVE},
	"rslave":      {set: true, val: syscall.MS_SLAVE | syscall.MS_REC},
	"unbindable":  {set: true, val: syscall.MS_UNBINDABLE},
	"runbindable": {set: true, val: syscall.MS_UNBINDABLE | syscall.MS_REC},
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
// handled separatedly.
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

// ValidateMount validates that spec mounts are correct.
func validateMount(mnt *specs.Mount) error {
	if !path.IsAbs(mnt.Destination) {
		return fmt.Errorf("Mount.Destination must be an absolute path: %v", mnt)
	}

	if mnt.Type == "bind" {
		for _, o := range mnt.Options {
			if ContainsStr(invalidOptions, o) {
				return fmt.Errorf("mount option %q is not supported: %v", o, mnt)
			}
			_, ok1 := optionsMap[o]
			_, ok2 := propOptionsMap[o]
			if !ok1 && !ok2 {
				return fmt.Errorf("unknown mount option %q", o)
			}
		}
	}
	return nil
}

// ValidateRootfsPropagation validates that rootfs propagation options are
// correct.
func validateRootfsPropagation(opt string) error {
	flags := PropOptionsToFlags([]string{opt})
	if flags&(syscall.MS_SLAVE|syscall.MS_PRIVATE) == 0 {
		return fmt.Errorf("root mount propagation option must specify private or slave: %q", opt)
	}
	return nil
}
