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

package stack

import (
	"time"
)

// +stateify savable
type unixTime struct {
	second int64
	nano   int64
}

// saveLastUsed is invoked by stateify.
func (cn *conn) saveLastUsed() unixTime {
	cn.mu.Lock()
	defer cn.mu.Unlock()
	return unixTime{cn.lastUsed.Unix(), cn.lastUsed.UnixNano()}
}

// loadLastUsed is invoked by stateify.
func (cn *conn) loadLastUsed(unix unixTime) {
	cn.mu.Lock()
	defer cn.mu.Unlock()
	cn.lastUsed = time.Unix(unix.second, unix.nano)
}

// beforeSave is invoked by stateify.
func (ct *ConnTrack) beforeSave() {
	ct.mu.Lock()
}
