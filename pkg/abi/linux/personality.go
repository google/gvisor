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

package linux

// Personality flags, used by personality(2),
// from include/uapi/linux/personality.h.
const (
	SHORT_INODE   = 0x1000000
	WHOLE_SECONDS = 0x2000000
	PER_LINUX     = 0x0000
	PER_BSD       = 0x0006
)

// NOTE: All of the above flags are non-security-sensitive and may be copied
// from parent task to child task. However, this is not the case for all
// personality bits. If adding more, check PER_CLEAR_ON_SETID and ensure that
// these are cleared on suid/sgid execs.
