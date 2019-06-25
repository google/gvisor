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

// +build go1.13
// +build !go1.14

// TODO(b/133868570): Delete once Go 1.12 is no longer supported.

package console

// CttyFdIsPostShuffle indicates that in go1.13 and later, the SysProcAttr.Ctty
// FD is determined "post-shuffle".
var CttyFdIsPostShuffle = true
