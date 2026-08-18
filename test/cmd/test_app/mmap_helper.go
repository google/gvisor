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

package main

import (
	"context"
	"fmt"
	"os"
	sys "syscall"
	"time"

	"github.com/google/subcommands"
	"gvisor.dev/gvisor/runsc/flag"
)

// mmapHelper is a test helper command used in checkpoint/restore integration
// tests (such as combined_restore_test.go).
//
// It performs the following sequence to allow synchronization with the host:
//  1. Opens/creates a target file and writes initial content.
//  2. Memory maps the file via mmap (MAP_SHARED) and touches the mapping to
//     populate it.
//  3. Signals the host that it is ready by creating a "ready" file. This tells
//     the host test runner that it is safe to take a checkpoint.
//  4. Blocks and polls waiting for a "go" file (defined by -go) to appear. The
//     process remains blocked here during checkpoint and subsequent restore.
//  5. Once the "go" file is created by the host (post-restore), it resumes,
//     reads the content of the target file via ReadFile, writes it to an output
//     file, and verifies both memory mapping and file content against -want.
//
// This synchronization is necessary because checkpoints can only be taken
// while the container process is running. Files in shared mounts are used as
// synchronization signals between the host test runner and the guest app
// inside the sandbox.
type mmapHelper struct {
	file    string
	ready   string
	goFile  string
	output  string
	dummy   string
	content string
	want    string
}

// Name implements subcommands.Command.Name.
func (*mmapHelper) Name() string {
	return "mmap-helper"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*mmapHelper) Synopsis() string {
	return "maps a file, signals ready, waits for go, reads content, and verifies mapping after restore"
}

// Usage implements subcommands.Command.Usage.
func (*mmapHelper) Usage() string {
	return "mmap-helper <flags>"
}

// SetFlags implements subcommands.Command.SetFlags.
func (m *mmapHelper) SetFlags(f *flag.FlagSet) {
	f.StringVar(&m.file, "file", "", "path to file to map")
	f.StringVar(&m.ready, "ready", "", "path to ready file")
	f.StringVar(&m.goFile, "go", "", "path to go file")
	f.StringVar(&m.output, "output", "", "path to output file")
	f.StringVar(&m.dummy, "dummy", "", "path to dummy file")
	f.StringVar(&m.content, "content", "hello", "content to write to file")
	f.StringVar(&m.want, "want", "", "expected content to verify after restore")
}

func (m *mmapHelper) writeError(errMsg string) {
	fmt.Fprintf(os.Stderr, "mmap-helper error: %s\n", errMsg)
	if m.output != "" {
		_ = os.WriteFile(m.output, []byte("ERROR: "+errMsg), 0666)
	}
}

// Exit statuses for mmap-helper.
const (
	ExitMmapMismatch = subcommands.ExitStatus(10)
	ExitFileMismatch = subcommands.ExitStatus(11)
)

// Execute implements subcommands.Command.Execute.
func (m *mmapHelper) Execute(ctx context.Context, f *flag.FlagSet, _ ...any) subcommands.ExitStatus {
	if m.file == "" || m.ready == "" || m.goFile == "" {
		fmt.Printf("missing required flags\n")
		return subcommands.ExitUsageError
	}

	if m.dummy != "" {
		if err := os.WriteFile(m.dummy, []byte("a"), 0666); err != nil {
			m.writeError(fmt.Sprintf("failed to write dummy file: %v", err))
			return subcommands.ExitFailure
		}
	}

	fd, err := sys.Open(m.file, sys.O_CREAT|sys.O_RDWR|sys.O_TRUNC, 0666)
	if err != nil {
		m.writeError(fmt.Sprintf("failed to open file: %v", err))
		return subcommands.ExitFailure
	}
	defer sys.Close(fd)

	contentBytes := []byte(m.content)
	n, err := sys.Write(fd, contentBytes)
	if err != nil || n != len(contentBytes) {
		m.writeError(fmt.Sprintf("failed to write content: %v, %d", err, n))
		return subcommands.ExitFailure
	}

	data, err := sys.Mmap(fd, 0, 4096, sys.PROT_READ, sys.MAP_SHARED)
	if err != nil {
		m.writeError(fmt.Sprintf("mmap failed: %v", err))
		return subcommands.ExitFailure
	}
	defer func() {
		_ = sys.Munmap(data)
	}()
	if len(contentBytes) > 0 {
		fmt.Fprintf(os.Stderr, "Touch mapping: %c\n", data[0])
	}

	// Write ready file to indicate that a checkpoint has to be taken.
	readyFile, err := os.Create(m.ready)
	if err != nil {
		m.writeError(fmt.Sprintf("failed to create ready file: %v", err))
		return subcommands.ExitFailure
	}
	readyFile.Close()

	// Wait for go file to be created to indicate the restore is complete.
	deadline := time.Now().Add(60 * time.Second)
	for {
		if _, err := os.Stat(m.goFile); err == nil {
			break
		}
		if time.Now().After(deadline) {
			m.writeError(fmt.Sprintf("timed out waiting for go file %q", m.goFile))
			return subcommands.ExitFailure
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Read content from cleanly restored filesystem.
	contentBytes, readErr := os.ReadFile(m.file)
	if readErr != nil {
		m.writeError(fmt.Sprintf("failed to read file: %v", readErr))
		return subcommands.ExitFailure
	}

	if m.output != "" {
		err = os.WriteFile(m.output, contentBytes, 0666)
		if err != nil {
			fmt.Printf("failed to write output file: %v\n", err)
			return subcommands.ExitFailure
		}
	}

	if m.want != "" {
		if len(data) < len(m.want) || string(data[:len(m.want)]) != m.want {
			m.writeError(fmt.Sprintf("mmap content mismatch: got %q, want %q", string(data[:len(m.want)]), m.want))
			return ExitMmapMismatch
		}
		if string(contentBytes) != m.want {
			m.writeError(fmt.Sprintf("file content mismatch: got %q, want %q", string(contentBytes), m.want))
			return ExitFileMismatch
		}
	}

	return subcommands.ExitSuccess
}
