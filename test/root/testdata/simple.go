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

package testdata

import (
	"encoding/json"
	"fmt"
)

// SimpleSpec returns a JSON config for a simple container that runs the
// specified command in the specified image.
func SimpleSpec(name, image string, cmd []string) string {
	cmds, err := json.Marshal(cmd)
	if err != nil {
		// This shouldn't happen.
		panic(err)
	}
	return fmt.Sprintf(`
{
        "metadata": {
                "name": %q
        },
        "image": {
                "image": %q
        },
        "command": %s
	}
`, name, image, cmds)
}
