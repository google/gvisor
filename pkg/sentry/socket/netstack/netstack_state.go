// Copyright 2021 The gVisor Authors.
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

package netstack

import (
	"context"
	"time"
)

func (s *sock) saveTimestamp() int64 {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	return s.timestamp.UnixNano()
}

func (s *sock) loadTimestamp(_ context.Context, nsec int64) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	s.timestamp = time.Unix(0, nsec)
}
