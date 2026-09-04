// Copyright 2026 The gVisor Authors.
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

// Package tpucontrol implements a host-side client for the libtpu
// checkpoint/restore control protocol.
//
// libtpu advertises its control channel by naming a thread
// "libtpu{XXXXYYYY}", where XXXX and YYYY are the hex-encoded file
// descriptor numbers of the request-write and response-read pipes. This
// package discovers those threads via /proc and exchanges length-delimited
// protobuf messages over the pipes.
package tpucontrol

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const threadNamePrefix = "libtpu"

// ProcRoot is the base path for /proc. Overridable for tests.
var ProcRoot = "/proc"

// PipeInfo holds the pipe file descriptor numbers extracted from a libtpu
// thread name.
type PipeInfo struct {
	TID        int
	ThreadName string
	ReqWriteFD int
	RspReadFD  int
}

// DiscoverPipes scans /proc/<pid>/task/*/comm for threads named
// "libtpu{XXXXYYYY}" and extracts the pipe FD numbers encoded in the hex
// suffix.
func DiscoverPipes(pid int) ([]PipeInfo, error) {
	taskDir := fmt.Sprintf("%s/%d/task", ProcRoot, pid)
	entries, err := os.ReadDir(taskDir)
	if err != nil {
		return nil, fmt.Errorf("read task dir %s: %w", taskDir, err)
	}

	var pipes []PipeInfo
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		tid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}

		commPath := filepath.Join(taskDir, e.Name(), "comm")
		data, err := os.ReadFile(commPath)
		if err != nil {
			continue
		}
		name := strings.TrimSpace(string(data))

		if !strings.HasPrefix(name, threadNamePrefix) {
			continue
		}
		hexSuffix := strings.TrimPrefix(name, threadNamePrefix)
		if len(hexSuffix) != 8 {
			continue
		}

		reqFD, err := strconv.ParseInt(hexSuffix[:4], 16, 32)
		if err != nil {
			continue
		}
		rspFD, err := strconv.ParseInt(hexSuffix[4:], 16, 32)
		if err != nil {
			continue
		}

		pipes = append(pipes, PipeInfo{
			TID:        tid,
			ThreadName: name,
			ReqWriteFD: int(reqFD),
			RspReadFD:  int(rspFD),
		})
	}

	if len(pipes) == 0 {
		return nil, fmt.Errorf("no libtpu threads found for PID %d", pid)
	}
	return pipes, nil
}

// PipePath returns the /proc path used to access a file descriptor of
// another process.
func PipePath(pid, fd int) string {
	return fmt.Sprintf("%s/%d/fd/%d", ProcRoot, pid, fd)
}
