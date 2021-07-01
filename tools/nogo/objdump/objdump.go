// Copyright 2020 The gVisor Authors.
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

// Package objdump is a wrapper around relevant objdump flags.
package objdump

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
)

var (
	// Binary is the binary under analysis.
	//
	// See Reader, below.
	binary = flag.String("binary", "", "binary under analysis")

	// Reader is the input stream.
	//
	// This may be set instead of Binary.
	Reader io.Reader

	// objdumpTool is the tool used to dump a binary.
	objdumpTool = flag.String("objdump_tool", "", "tool used to dump a binary")
)

// LoadRaw reads the raw object output.
func LoadRaw(fn func(r io.Reader) error) error {
	var r io.Reader
	if *binary != "" {
		f, err := os.Open(*binary)
		if err != nil {
			return err
		}
		defer f.Close()
		r = f
	} else if Reader != nil {
		r = Reader
	} else {
		// We have no input stream.
		return fmt.Errorf("no binary or reader provided")
	}
	return fn(r)
}

// Load reads the objdump output.
func Load(fn func(r io.Reader) error) error {
	var (
		args  []string
		stdin io.Reader
	)
	if *binary != "" {
		args = append(args, *binary)
	} else if Reader != nil {
		stdin = Reader
	} else {
		// We have no input stream or binary.
		return fmt.Errorf("no binary or reader provided")
	}

	// Construct our command.
	cmd := exec.Command(*objdumpTool, args...)
	cmd.Stdin = stdin
	cmd.Stderr = os.Stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}

	// Call the user hook.
	userErr := fn(out)

	// Wait for the dump to finish.
	if err := cmd.Wait(); userErr == nil && err != nil {
		return err
	}

	return userErr
}
