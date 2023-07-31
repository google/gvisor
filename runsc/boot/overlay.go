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

// OverlayMedium describes the medium that will be used to back the
// overlay mount's upper layer.
type OverlayMedium int

const (
	// NoOverlay indicates that this mount should not be overlaid.
	NoOverlay OverlayMedium = iota

	// MemoryMedium indicates that this mount should be overlaid with an
	// upper layer backed by application memory.
	MemoryMedium

	// SelfMedium indicates that this mount should be overlaid with an upper
	// layer backed by a host file in the mount's source directory.
	SelfMedium

	// AnonDirMedium indicates that this mount should be overlaid with an upper
	// layer backed by a host file in an anonymous directory.
	AnonDirMedium
)

// IsBackedByHostFile returns true if the overlay is backed by a host file.
func (o *OverlayMedium) IsBackedByHostFile() bool {
	return *o == SelfMedium || *o == AnonDirMedium
}

// IsEnabled returns true if an overlay is applied.
func (o *OverlayMedium) IsEnabled() bool {
	return *o != NoOverlay
}

// OverlayMediumFlags can be used with OverlayMedium flags that appear
// multiple times.
type OverlayMediumFlags []OverlayMedium

// String implements flag.Value.
func (o *OverlayMediumFlags) String() string {
	mediumVals := make([]string, 0, len(*o))
	for _, medium := range *o {
		mediumVals = append(mediumVals, strconv.Itoa(int(medium)))
	}
	return strings.Join(mediumVals, ",")
}

// Get implements flag.Value.
func (o *OverlayMediumFlags) Get() any {
	return o
}

// GetArray returns an array of mappings.
func (o *OverlayMediumFlags) GetArray() []OverlayMedium {
	return *o
}

// Set implements flag.Value and appends an overlay medium from the command
// line to the mediums array. Set(String()) should be idempotent.
func (o *OverlayMediumFlags) Set(s string) error {
	mediums := strings.Split(s, ",")
	for _, medium := range mediums {
		mediumVal, err := strconv.Atoi(medium)
		if err != nil {
			return fmt.Errorf("invalid OverlayMedium value (%d): %v", mediumVal, err)
		}
		if mediumVal > int(AnonDirMedium) {
			return fmt.Errorf("invalid OverlayMedium value (%d)", mediumVal)
		}
		*o = append(*o, OverlayMedium(mediumVal))
	}
	return nil
}
