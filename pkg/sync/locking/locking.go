// Copyright 2022 The gVisor Authors.
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

// Package locking implements lock primitives with the correctness validator.
//
// All mutexes are divided on classes and the validator check following conditions:
//   - Mutexes of the same class are not taken more than once except cases when
//     that is expected.
//   - Mutexes are never locked in a reverse order. Lock dependencies are tracked
//     on the class level.
//
// The validator is implemented in a very straightforward way. For each mutex
// class, we maintain the ancestors list of all classes that have ever been
// taken before the target one. For each goroutine, we have the list of
// currently locked mutexes. And finally, all lock methods check that
// ancestors of currently locked mutexes don't contain the target one.
package locking
