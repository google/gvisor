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

//go:build !false
// +build !false

package config

// Bundles is the set of each Bundle.
// Each bundle is a named set of flag names and flag values.
// Bundles may be turned on using pod annotations.
// Bundles have lower precedence than flag pod annotation and command-line flags.
// Bundles are mutually exclusive iff their flag values overlap and differ.
var Bundles = map[BundleName]Bundle{
	"experimental-high-performance": {
		"directfs": "true",
		"overlay2": "root:self",
		"platform": "systrap",
	},
}
