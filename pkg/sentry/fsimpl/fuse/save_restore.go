// Copyright 2024 The gVisor Authors.
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

package fuse

import "context"

func (fRes *futureResponse) afterLoad(context.Context) {
	fRes.ch = make(chan struct{})
}

func (conn *connection) saveFullQueueCh() int {
	return cap(conn.fullQueueCh)
}

func (conn *connection) loadFullQueueCh(_ context.Context, capacity int) {
	conn.fullQueueCh = make(chan struct{}, capacity)
}
