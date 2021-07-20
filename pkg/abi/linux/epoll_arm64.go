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

//go:build arm64
// +build arm64

package linux

// EpollEvent is equivalent to struct epoll_event from epoll(2).
//
// +marshal slice:EpollEventSlice
type EpollEvent struct {
	Events uint32
	// Linux makes struct epoll_event a __u64, necessitating 4 bytes of padding
	// here.
	_    int32
	Data [2]int32
}
