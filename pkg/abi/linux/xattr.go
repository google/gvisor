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

package linux

// Constants for extended attributes.
const (
	XATTR_NAME_MAX = 255
	XATTR_SIZE_MAX = 65536

	XATTR_CREATE  = 1
	XATTR_REPLACE = 2

	XATTR_USER_PREFIX     = "user."
	XATTR_USER_PREFIX_LEN = len(XATTR_USER_PREFIX)
)
