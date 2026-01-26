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

//go:build !amd64

// This file is intentionally left blank. Other arches don't use
// addrOfSpinning, but because this package is partially used in Netstack, we
// should support arches that aren't amd64 or arm64. Having this file here
// ensures that `go build` doesn't compile the package with the `-complete`
// flag, because the package isn't made up of just '.go' files.
// This allows Netstack to use the architecture-independent portions of this
// package, because the architecture-dependent portions are never compiled in
// the first place.
