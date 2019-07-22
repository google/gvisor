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

// Package runtimes provides language tests for runsc runtimes.
// Each test calls docker commands to start up a container for each supported runtime,
// and tests that its respective language tests are behaving as expected, like
// connecting to a port or looking at the output. The container is killed and deleted
// at the end.
package runtimes
