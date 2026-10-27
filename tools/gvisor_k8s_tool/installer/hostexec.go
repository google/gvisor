// Copyright The Isola Authors
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

package installer

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
)

// HostExec runs a command in the host's mount namespace, so host binaries and
// paths resolve as the node sees them.
type HostExec interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// nsenterExec depends on the DaemonSet's hostPID (so PID 1 is the host's init,
// not the container's) and privileged (so setns is permitted).
type nsenterExec struct{}

func NewNsenterExec() HostExec { return nsenterExec{} }

func (nsenterExec) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	nsenterArgs := append([]string{"--target", "1", "--mount", "--root", "--wd=/proc/1/root", "--", name}, args...)
	cmd := exec.CommandContext(ctx, "nsenter", nsenterArgs...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stdout.Bytes(), fmt.Errorf("host command %q failed: %w (stderr: %s)", name, err, truncateOutput(stderr.Bytes()))
	}
	return stdout.Bytes(), nil
}

// truncateOutput bounds output embedded in errors, which end up in node
// events (size-capped by the API server).
func truncateOutput(b []byte) string {
	const maxLen = 1024
	s := string(bytes.TrimSpace(b))
	if len(s) > maxLen {
		return s[:maxLen] + "...(truncated)"
	}
	return s
}
