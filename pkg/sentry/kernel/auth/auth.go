// Copyright 2018 The gVisor Authors.
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

// Package auth implements an access control model that is a subset of Linux's.
//
// The auth package supports two kinds of access controls: user/group IDs and
// capabilities. Each resource in the security model is associated with a user
// namespace; "privileged" operations check that the operator's credentials
// have the required user/group IDs or capabilities within the user namespace
// of accessed resources.
package auth
