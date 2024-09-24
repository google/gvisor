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

// Package nvconf provides configuration structures and utilities for nvproxy.
//
// This package is separate from the main nvproxy package to allow reading and
// working with nvproxy configuration without importing the full nvproxy
// package and its dependencies. This is useful for tools and applications that
// only need to interact with the configuration.
package nvconf
