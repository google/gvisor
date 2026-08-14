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
//  1. Opens/creates a target file (defined by -file) and writes initial content.
//  2. Optionally mmaps the file (default) or uses standard pread (-read).
//  3. Signals the host that it is ready by creating a "ready" file (defined by -ready).
//     This tells the host test runner that it is safe to take a checkpoint.
//  4. Blocks and polls waiting for a "go" file (defined by -go) to appear.
//     The process remains blocked here during the checkpoint and subsequent restore.
//  5. Once the "go" file is created by the host (post-restore), it resumes, reads
//     the content of the target file (verifying memory mappings or reads work after
//     restore), and writes the content to an output file (defined by -output).
//
// This is necessary because checkpoints can only be taken while the container
// process is running. Shared files in the bind mount are used as signal for
// the host from inside the isolated sandbox.
type mmapHelper struct {
	file    string
	ready   string
	goFile  string
	output  string
	dummy   string
	content string
}

// Name implements subcommands.Command.Name.
func (*mmapHelper) Name() string {
	return "mmap-helper"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*mmapHelper) Synopsis() string {
	return "maps or reads a file, signals ready, waits for go, reads content, writes to output file"
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
}

func (m *mmapHelper) writeError(errMsg string) {
	if m.output != "" {
		_ = os.WriteFile(m.output, []byte("ERROR: "+errMsg), 0666)
	}
}

// Execute implements subcommands.Command.Execute.
func (m *mmapHelper) Execute(ctx context.Context, f *flag.FlagSet, _ ...any) subcommands.ExitStatus {
	if m.file == "" || m.ready == "" || m.goFile == "" || m.output == "" {
		fmt.Printf("missing required flags\n")
		return subcommands.ExitUsageError
	}

	if m.dummy != "" {
		dfd, err := sys.Open(m.dummy, sys.O_CREAT|sys.O_WRONLY, 0666)
		if err != nil {
			m.writeError(fmt.Sprintf("failed to open dummy file: %v", err))
			return subcommands.ExitFailure
		}
		n, err := sys.Write(dfd, []byte("a"))
		if err != nil || n != 1 {
			m.writeError(fmt.Sprintf("failed to write dummy file: %v, %d", err, n))
			sys.Close(dfd)
			return subcommands.ExitFailure
		}
		sys.Close(dfd)
	}

	fd, err := sys.Open(m.file, sys.O_CREAT|sys.O_RDWR, 0666)
	if err != nil {
		m.writeError(fmt.Sprintf("failed to open file: %v", err))
		return subcommands.ExitFailure
	}
	defer sys.Close(fd)

	// Write initial content if the file is empty.
	var stat sys.Stat_t
	if err := sys.Fstat(fd, &stat); err != nil {
		m.writeError(fmt.Sprintf("failed to fstat: %v", err))
		return subcommands.ExitFailure
	}
	if stat.Size == 0 {
		contentBytes := []byte(m.content)
		n, err := sys.Write(fd, contentBytes)
		if err != nil || n != len(contentBytes) {
			m.writeError(fmt.Sprintf("failed to write initial content: %v, %d", err, n))
			return subcommands.ExitFailure
		}
	}

	data, err := sys.Mmap(fd, 0, 4096, sys.PROT_READ, sys.MAP_SHARED)
	if err != nil {
		m.writeError(fmt.Sprintf("mmap failed: %v", err))
		return subcommands.ExitFailure
	}
	defer func() {
		_ = sys.Munmap(data)
	}()
	fmt.Fprintf(os.Stderr, "Touch mapping: %c\n", data[0])

	// Write ready file to indicate that a checkpoint has to be taken.
	readyFile, err := os.Create(m.ready)
	if err != nil {
		m.writeError(fmt.Sprintf("failed to create ready file: %v", err))
		return subcommands.ExitFailure
	}
	readyFile.Close()

	// Wait for go file to be created to indicate the restore is complete.
	timeout := 10 * time.Second
	start := time.Now()
	for {
		if _, err := os.Stat(m.goFile); err == nil {
			break
		}
		if time.Since(start) > timeout {
			m.writeError("timeout waiting for go file")
			return subcommands.ExitFailure
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Read from mapping.
	content := string(data[:len(m.content)])

	// Write to output file.
	err = os.WriteFile(m.output, []byte(content), 0666)
	if err != nil {
		fmt.Printf("failed to write output file: %v\n", err)
		return subcommands.ExitFailure
	}

	return subcommands.ExitSuccess
}
