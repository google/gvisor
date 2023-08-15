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

package helloworld_test

import (
	"context"
	"fmt"
	"os/exec"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/test/testutil"
)

// TestHelloworld executes helloworld_bundler and verifies that its output
// matches "Hello, gVisor!\n".
func TestHelloworld(t *testing.T) {
	ctx, ctxCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer ctxCancel()
	helloWorldPath, err := testutil.FindFile("tools/embeddedbinary/test/helloworld_bundler")
	if err != nil {
		t.Fatalf("Cannot find helloworld_bundler path: %v", err)
	}
	for _, mode := range []string{"exec", "fork"} {
		t.Run(mode, func(t *testing.T) {
			output, err := exec.CommandContext(ctx, helloWorldPath, fmt.Sprintf("--mode=%s", mode)).CombinedOutput()
			outputStr := string(output)
			if err != nil {
				t.Fatalf("Failed to execute helloworld_bundler: %v; output:\n%v\n", err, outputStr)
			}
			want := "Hello, gVisor!\n"
			if outputStr != want {
				t.Fatalf("helloworld_bundler: got output %q want %q", outputStr, want)
			}
		})
	}
}
