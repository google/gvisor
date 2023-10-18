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

package boot

import (
	"fmt"
	"strconv"
	"strings"
)

// GoferMountConf describes how a gofer mount is configured in the sandbox.
type GoferMountConf int

const (
	// VanillaGofer indicates that this gofer mount has no special configuration.
	VanillaGofer GoferMountConf = iota

	// MemoryOverlay indicates that this gofer mount should be overlaid with an
	// overlayfs backed by application memory.
	MemoryOverlay

	// SelfOverlay indicates that this gofer mount should be overlaid with an
	// overlayfs backed by a host file in the mount's source directory.
	SelfOverlay

	// AnonOverlay indicates that this gofer mount should be overlaid with an
	// overlayfs backed by a host file in an anonymous directory.
	AnonOverlay

	// SelfTmpfs indicates that this gofer mount should be overlaid with a tmpfs
	// mount backed by a host file in the mount's source directory.
	SelfTmpfs
)

// IsFilestorePresent returns true if a filestore file was associated with this.
func (g GoferMountConf) IsFilestorePresent() bool {
	return g == SelfOverlay || g == AnonOverlay || g == SelfTmpfs
}

// IsSelfBacked returns true if this mount is backed by a filestore in itself.
func (g GoferMountConf) IsSelfBacked() bool {
	return g == SelfOverlay || g == SelfTmpfs
}

// ShouldUseOverlayfs returns true if an overlayfs should be applied.
func (g GoferMountConf) ShouldUseOverlayfs() bool {
	return g == MemoryOverlay || g == SelfOverlay || g == AnonOverlay
}

// ShouldUseLisafs returns true if a lisafs client/server should be set up.
func (g GoferMountConf) ShouldUseLisafs() bool {
	return g == VanillaGofer || g.ShouldUseOverlayfs()
}

// GoferMountConfFlags can be used with GoferMountConf flags that appear
// multiple times.
type GoferMountConfFlags []GoferMountConf

// String implements flag.Value.
func (g *GoferMountConfFlags) String() string {
	confVals := make([]string, 0, len(*g))
	for _, confVal := range *g {
		confVals = append(confVals, strconv.Itoa(int(confVal)))
	}
	return strings.Join(confVals, ",")
}

// Get implements flag.Value.
func (g *GoferMountConfFlags) Get() any {
	return g
}

// GetArray returns an array of mappings.
func (g *GoferMountConfFlags) GetArray() []GoferMountConf {
	return *g
}

// Set implements flag.Value and appends a gofer configuration from the command
// line to the configs array. Set(String()) should be idempotent.
func (g *GoferMountConfFlags) Set(s string) error {
	confs := strings.Split(s, ",")
	for _, conf := range confs {
		confVal, err := strconv.Atoi(conf)
		if err != nil {
			return fmt.Errorf("invalid GoferMountConf value (%d): %v", confVal, err)
		}
		if confVal > int(SelfTmpfs) {
			return fmt.Errorf("invalid GoferMountConf value (%d)", confVal)
		}
		*g = append(*g, GoferMountConf(confVal))
	}
	return nil
}
