// Copyright 2019 The gVisor Authors.
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

//go:build amd64
// +build amd64

package linux

// EpollEvent is equivalent to struct epoll_event from epoll(2).
//
// +marshal slice:EpollEventSlice
type EpollEvent struct {
	Events uint32
	// Linux makes struct epoll_event::data a __u64. We represent it as
	// [2]int32 because, on amd64, Linux also makes struct epoll_event
	// __attribute__((packed)), such that there is no padding between Events
	// and Data.
	Data [2]int32
}
