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
	"strings"

	"gvisor.dev/gvisor/pkg/sentry/fsimpl/erofs"
)

// GoferMountConfUpperType describes how upper layer is configured for the gofer mount.
type GoferMountConfUpperType byte

const (
	// NoOverlay indicates that this gofer mount has no upper layer. In this case,
	// this gofer mount must have a lower layer (i.e. lower != NoneLower).
	NoOverlay GoferMountConfUpperType = iota

	// MemoryOverlay indicates that this gofer mount should be overlaid with a
	// tmpfs backed by application memory.
	MemoryOverlay

	// SelfOverlay indicates that this gofer mount should be overlaid with a
	// tmpfs backed by a host file in the mount's source directory.
	SelfOverlay

	// AnonOverlay indicates that this gofer mount should be overlaid with a
	// tmpfs backed by a host file in an anonymous directory.
	AnonOverlay

	// UpperMax indicates the number of the valid upper layer types.
	UpperMax
)

// String returns a human-readable string representing the upper layer type.
func (u GoferMountConfUpperType) String() string {
	switch u {
	case NoOverlay:
		return "none"
	case MemoryOverlay:
		return "memory"
	case SelfOverlay:
		return "self"
	case AnonOverlay:
		return "anon"
	}
	panic(fmt.Sprintf("Invalid gofer mount config upper layer type: %d", u))
}

// Set sets the value. Set(String()) should be idempotent.
func (u *GoferMountConfUpperType) Set(v string) error {
	switch v {
	case "none":
		*u = NoOverlay
	case "memory":
		*u = MemoryOverlay
	case "self":
		*u = SelfOverlay
	case "anon":
		*u = AnonOverlay
	default:
		return fmt.Errorf("invalid gofer mount config upper layer type: %s", v)
	}
	return nil
}

// GoferMountConfLowerType describes how lower layer is configured for the gofer mount.
type GoferMountConfLowerType byte

const (
	// NoneLower indicates that this gofer mount has no lower layer.
	NoneLower GoferMountConfLowerType = iota

	// Lisafs indicates that this gofer mount has a LISAFS lower layer.
	Lisafs

	// Erofs indicates that this gofer mount has an EROFS lower layer.
	Erofs

	// LowerMax indicates the number of the valid lower layer types.
	LowerMax
)

// String returns a human-readable string representing the lower layer type.
func (l GoferMountConfLowerType) String() string {
	switch l {
	case NoneLower:
		return "none"
	case Lisafs:
		return "lisafs"
	case Erofs:
		return erofs.Name
	}
	panic(fmt.Sprintf("Invalid gofer mount config lower layer type: %d", l))
}

// Set sets the value. Set(String()) should be idempotent.
func (l *GoferMountConfLowerType) Set(v string) error {
	switch v {
	case "none":
		*l = NoneLower
	case "lisafs":
		*l = Lisafs
	case erofs.Name:
		*l = Erofs
	default:
		return fmt.Errorf("invalid gofer mount config lower layer type: %s", v)
	}
	return nil
}

// GoferMountConf describes how a gofer mount is configured in the sandbox.
type GoferMountConf struct {
	Upper GoferMountConfUpperType `json:"upper"`
	Lower GoferMountConfLowerType `json:"lower"`
}

// String returns a human-readable string representing the gofer mount config.
func (g GoferMountConf) String() string {
	return fmt.Sprintf("%s:%s", g.Lower, g.Upper)
}

// Set sets the value. Set(String()) should be idempotent.
func (g *GoferMountConf) Set(v string) error {
	parts := strings.Split(v, ":")
	if len(parts) != 2 {
		return fmt.Errorf("invalid gofer mount config format: %q", v)
	}
	if err := g.Lower.Set(parts[0]); err != nil {
		return err
	}
	if err := g.Upper.Set(parts[1]); err != nil {
		return err
	}
	if !g.valid() {
		return fmt.Errorf("invalid gofer mount config: %+v", g)
	}
	return nil
}

// IsFilestorePresent returns true if a filestore file was associated with this.
func (g GoferMountConf) IsFilestorePresent() bool {
	return g.Upper == SelfOverlay || g.Upper == AnonOverlay
}

// IsSelfBacked returns true if this mount is backed by a filestore in itself.
func (g GoferMountConf) IsSelfBacked() bool {
	return g.Upper == SelfOverlay
}

// ShouldUseOverlayfs returns true if an overlayfs should be applied.
func (g GoferMountConf) ShouldUseOverlayfs() bool {
	return g.Lower != NoneLower && g.Upper != NoOverlay
}

// ShouldUseTmpfs returns true if a tmpfs should be applied.
func (g GoferMountConf) ShouldUseTmpfs() bool {
	// g.valid() implies that g.Upper != NoOverlay.
	return g.Lower == NoneLower
}

// ShouldUseLisafs returns true if a lisafs client/server should be set up.
func (g GoferMountConf) ShouldUseLisafs() bool {
	return g.Lower == Lisafs
}

// ShouldUseErofs returns true if an EROFS should be applied.
func (g GoferMountConf) ShouldUseErofs() bool {
	return g.Lower == Erofs
}

// valid returns true if this is a valid gofer mount config.
func (g GoferMountConf) valid() bool {
	return g.Lower < LowerMax && g.Upper < UpperMax && (g.Lower != NoneLower || g.Upper != NoOverlay)
}

// GoferMountConfFlags can be used with GoferMountConf flags that appear
// multiple times.
type GoferMountConfFlags []GoferMountConf

// String implements flag.Value.
func (g *GoferMountConfFlags) String() string {
	confs := make([]string, 0, len(*g))
	for _, confVal := range *g {
		confs = append(confs, confVal.String())
	}
	return strings.Join(confs, ",")
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
		var confVal GoferMountConf
		if err := confVal.Set(conf); err != nil {
			return fmt.Errorf("invalid GoferMountConf value (%s): %v", conf, err)
		}
		*g = append(*g, confVal)
	}
	return nil
}
