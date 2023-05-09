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

package tcp

// saveOptions is invoked by stateify.
func (s *segment) saveOptions() []byte {
	// We cannot save s.options directly as it may point to s.data's trimmed
	// tail, which is not allowed by state framework (in-struct pointer).
	b := make([]byte, 0, cap(s.options))
	return append(b, s.options...)
}

// loadOptions is invoked by stateify.
func (s *segment) loadOptions(options []byte) {
	// NOTE: We cannot point s.options back into s.data's trimmed tail. But
	// it is OK as they do not need to aliased. Plus, options is already
	// allocated so there is no cost here.
	s.options = options
}
