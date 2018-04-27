// Copyright 2018 Google Inc.
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

package kernel

// Version defines the application-visible system version.
type Version struct {
	// Operating system name (e.g. "Linux").
	Sysname string

	// Operating system release (e.g. "3.11.10-amd64").
	Release string

	// Operating system version. On Linux this takes the shape
	// "#VERSION CONFIG_FLAGS TIMESTAMP"
	// where:
	// - VERSION is a sequence counter incremented on every successful build
	// - CONFIG_FLAGS is a space-separated list of major enabled kernel features
	//   (e.g. "SMP" and "PREEMPT")
	// - TIMESTAMP is the build timestamp as returned by `date`
	Version string
}
