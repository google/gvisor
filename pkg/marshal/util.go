// Copyright 2020 The gVisor Authors.
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

package marshal

// Marshal returns the serialized contents of m in a newly allocated
// byte slice.
func Marshal(m Marshallable) []byte {
	buf := make([]byte, m.SizeBytes())
	m.MarshalUnsafe(buf)
	return buf
}

// MarshalAll returns the serialized contents of all ms in a newly allocated
// byte slice.
func MarshalAll(ms []Marshallable) []byte {
	buf := make([]byte, TotalSize(ms))
	var written int
	for _, m := range ms {
		m.MarshalUnsafe(buf[written:])
		written += m.SizeBytes()
	}
	return buf
}

// TotalSize returns the total size of all ms.
func TotalSize(ms []Marshallable) int {
	var size int
	for _, m := range ms {
		size += m.SizeBytes()
	}
	return size
}
