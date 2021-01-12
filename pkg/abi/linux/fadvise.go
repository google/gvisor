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

package linux

// Fadvise constants.
const (
	POSIX_FADV_NORMAL     = 0
	POSIX_FADV_RANDOM     = 1
	POSIX_FADV_SEQUENTIAL = 2
	POSIX_FADV_WILLNEED   = 3
	POSIX_FADV_DONTNEED   = 4
	POSIX_FADV_NOREUSE    = 5
)
