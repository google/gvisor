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

package linux

// Comands from linux/fcntl.h.
const (
	F_DUPFD         = 0
	F_DUPFD_CLOEXEC = 1030
	F_GETFD         = 1
	F_GETFL         = 3
	F_GETOWN        = 9
	F_SETFD         = 2
	F_SETFL         = 4
	F_SETLK         = 6
	F_SETLKW        = 7
	F_SETOWN        = 8
)

// Flags for fcntl.
const (
	FD_CLOEXEC = 00000001
)
