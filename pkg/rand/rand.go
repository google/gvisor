// Copyright 2018 Google Inc.
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

// Package rand implements a cryptographically secure pseudorandom number
// generator.
package rand

import (
	"io"

	"golang.org/x/sys/unix"
)

// reader implements an io.Reader that returns pseudorandom bytes.
type reader struct{}

// Read implements io.Reader.Read.
func (reader) Read(p []byte) (int, error) {
	return unix.Getrandom(p, 0)
}

// Reader is the default reader.
var Reader io.Reader = reader{}

// Read reads from the default reader.
func Read(b []byte) (int, error) {
	return io.ReadFull(Reader, b)
}
