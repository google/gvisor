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

package cmd

import (
	"os"

	"gvisor.dev/gvisor/runsc/cmd/util"
)

// getwdOrDie returns the current working directory and dies if it cannot.
func getwdOrDie() string {
	wd, err := os.Getwd()
	if err != nil {
		util.Fatalf("getting current working directory: %v", err)
	}
	return wd
}
