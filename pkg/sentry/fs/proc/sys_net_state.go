// Copyright 2018 Google LLC
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

package proc

import "fmt"

// afterLoad is invoked by stateify.
func (m *tcpMem) afterLoad() {
	if err := m.writeSize(); err != nil {
		panic(fmt.Sprintf("failed to write previous TCP send / receive buffer sizes [%v]: %v", m.size, err))
	}
}

// afterLoad is invoked by stateify.
func (s *tcpSack) afterLoad() {
	if s.enabled != nil {
		if err := s.s.SetTCPSACKEnabled(*s.enabled); err != nil {
			panic(fmt.Sprintf("failed to set previous TCP sack configuration [%v]: %v", *s.enabled, err))
		}
	}
}
