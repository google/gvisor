// Copyright 2023 The gVisor Authors.
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

//go:build !context_decoupling_disabled
// +build !context_decoupling_disabled

package systrap

// contextDecouplingExp is a global flag that enables thread decoupling mode.
// In this mode thread contexts are able to migrate between systrap user
// process threads. This also allows and enables the following experimental
// optimizations:
//   - Ability to run M contexts using N threads, where M > N.
//   - Reduce synchronization overhead between sentry threads and user
//     threads when switching contexts in and out of the sentry.
var contextDecouplingExp bool = true
