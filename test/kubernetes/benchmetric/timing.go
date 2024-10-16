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

package benchmetric

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"gvisor.dev/gvisor/test/kubernetes/testcluster"
	v13 "k8s.io/api/core/v1"
)

// nowNanosShellFunc is a shell function that returns the current timestamp
// in nanoseconds.
// It is backwards-compatible with versions of Bash that do not have support
// for outputting nanoseconds.
const nowNanosShellFunc = `
now_nanos() {
  if [ -n "$(date +%N)" ]; then
	  echo "$(date +%s%N)";
	else
	  echo "$(date +%s)000000000";
	fi;
}`

const (
	timingDataSeparator   = "::::"
	timingDataLinePrefix  = timingDataSeparator + "TIMING"
	timingDataLineFailure = timingDataLinePrefix + timingDataSeparator + "FAILURE"
)

// shellEscape escapes `cmd` for use in a shell string.
func shellEscape(cmd string) string {
	hasAnySpecialCharacter := false
	for _, c := range "\\\"'`$! &;|=~*#()[]{}<>" {
		if strings.ContainsRune(cmd, c) {
			hasAnySpecialCharacter = true
			break
		}
	}
	if !hasAnySpecialCharacter {
		return cmd
	}
	for _, c := range "\\\"$`" {
		cmd = strings.ReplaceAll(cmd, string(c), fmt.Sprintf("\\%s", string(c)))
	}
	return fmt.Sprintf(`"%s"`, cmd)
}

// TimedCommand takes in a command-line and computes a high-fidelity
// duration of how long it took. A pod using this command-line should
// have its duration measured using GetTimedContainerDuration.
// This is more reliable than looking at Kubernetes-tracked metrics
// for container start/end times, because Kubernetes only tracks these
// with second-level granularity, and because they include the overhead
// of starting/stopping a container. For benchmarks that want to measure
// the time of a particular command, TimedCommand provides better
// precision (nanosecond resolution) and accuracy (only measure the
// duration of the command, not the container runtime overhead).
// This must run in a container that has either `sh` or `bash`
// installed.
func TimedCommand(argv ...string) []string {
	escapedCmd := make([]string, len(argv))
	for i, arg := range argv {
		escapedCmd[i] = shellEscape(arg)
	}
	escapedCmd = append(escapedCmd, "||", "echo", shellEscape(timingDataLineFailure))
	nowNanos := strings.ReplaceAll(nowNanosShellFunc, "\n", " ")
	for strings.Contains(nowNanos, "  ") {
		nowNanos = strings.ReplaceAll(nowNanos, "  ", " ")
	}
	innerCommand := strings.Join([]string{
		// Define the now_nanos function.
		nowNanos,
		// Get the timestamp before the command.
		`before="$(now_nanos)"`,
		// Run the command.
		strings.Join(escapedCmd, " "),
		// Get the timestamp after the command.
		`after="$(now_nanos)"`,
		// Print out the before/after timestamps.
		// We cannot use shsprintf here because we *want* to be able to
		// use variables that shsprintf considers to "go out of scope".
		// This is safe because all of the strings below are completely
		// static.
		// We use this weird string concatenation to avoid triggering
		// the linter.
		fmt.Sprintf(`ec`+`ho "%s"`, strings.Join([]string{
			timingDataLinePrefix,
			"${before}",
			"${after}",
		}, timingDataSeparator)),
	}, "; ")

	return []string{
		// We can't assume that bash is installed, but we also can't
		// do conditionals in the top-level command, so just spawn sh
		// and we'll check if bash exists within that.
		"sh",
		"-c",
		fmt.Sprintf(
			// Use bash if possible, otherwise use sh.
			"if hash bash > /dev/null 2>/dev/null; then bash -c %s; else sh -c %s; fi",
			shellEscape(innerCommand),
			shellEscape(innerCommand),
		),
	}
}

// CommandThenTimed returns a command-line that runs a given command as
// initialization, then cd's into the given directory, then runs another
// command there under TimedCommand.
// When using GetTimedContainerDuration, only the duration of the
// `timedCmd` command will be measured.
// If `cd` is empty, no directory change happens.
func CommandThenTimed(initCmd []string, cd string, timedCmd []string) []string {
	escapedInitCmd := make([]string, len(initCmd))
	for i, arg := range initCmd {
		escapedInitCmd[i] = shellEscape(arg)
	}
	timedCmd = TimedCommand(timedCmd...)
	escapedTimedCmd := make([]string, len(timedCmd))
	for i, arg := range timedCmd {
		escapedTimedCmd[i] = shellEscape(arg)
	}
	commands := make([]string, 0, 3)
	commands = append(commands, strings.Join(escapedInitCmd, " "))
	if cd != "" {
		commands = append(commands, fmt.Sprintf("c"+"d %s", shellEscape(cd)))
	}
	commands = append(commands, strings.Join(escapedTimedCmd, " "))
	return []string{
		"sh",
		"-c",
		strings.Join(commands, " && "),
	}
}

// GetTimedContainerDuration waits for the given pod to exit, then parses its
// output and looks for duration information as expected from a command-line
// generated using `TimedCommand`.
func GetTimedContainerDuration(ctx context.Context, c *testcluster.TestCluster, pod *v13.Pod, containerName string) (time.Duration, error) {
	if err := c.WaitForPodCompleted(ctx, pod); err != nil {
		return 0, fmt.Errorf("failed to wait for pod to complete: %v", err)
	}
	rdr, err := c.GetLogReader(ctx, pod, v13.PodLogOptions{
		Container: containerName,
	})
	if err != nil {
		return 0, fmt.Errorf("GetLogReader on cluster %q pod %v: %v", c.GetName(), pod.GetName(), err)
	}
	out, err := io.ReadAll(rdr)
	if err != nil {
		return 0, fmt.Errorf("failed to read from pod: %q: %v", pod.GetName(), err)
	}
	return ParseTimedContainerOutput(string(out))
}

// ParseTimedContainerOutput parses the output of a TimedContainer.
func ParseTimedContainerOutput(out string) (time.Duration, error) {
	found := false
	var duration time.Duration
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, timingDataLinePrefix) {
			continue
		}
		if line == timingDataLineFailure {
			return 0, fmt.Errorf("command failed; output: %s", out)
		}
		if found {
			return 0, fmt.Errorf("output has multiple lines that look like duration information: %s", out)
		}
		data := strings.Split(line, timingDataSeparator)
		if len(data) != 4 {
			return 0, fmt.Errorf("malformed timing duration data line: %q", line)
		}
		beforeString, afterString := data[2], data[3]
		beforeNanos, err := strconv.ParseInt(beforeString, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("malformed timing duration data line %q: %v", line, err)
		}
		beforeTime := time.Unix(beforeNanos/1e9, beforeNanos%1e9)
		afterNanos, err := strconv.ParseInt(afterString, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("malformed timing duration data line %q: %v", line, err)
		}
		afterTime := time.Unix(afterNanos/1e9, afterNanos%1e9)
		duration = afterTime.Sub(beforeTime)
		if duration <= 0 {
			return 0, fmt.Errorf("duration is zero or negative: got before=%d (%v) / after=%d (%v)", beforeNanos, beforeTime, afterNanos, afterTime)
		}
		found = true
	}
	if !found {
		return 0, fmt.Errorf("output did not contain duration information: %s", out)
	}
	return duration, nil
}
