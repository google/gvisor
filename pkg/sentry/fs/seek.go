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

package fs

// SeekWhence determines seek direction.
type SeekWhence int

const (
	// SeekSet sets the absolute offset.
	SeekSet SeekWhence = iota

	// SeekCurrent sets relative to the current position.
	SeekCurrent

	// SeekEnd sets relative to the end of the file.
	SeekEnd
)

// String returns a human readable string for whence.
func (s SeekWhence) String() string {
	switch s {
	case SeekSet:
		return "Set"
	case SeekCurrent:
		return "Current"
	case SeekEnd:
		return "End"
	default:
		return "Unknown"
	}
}
