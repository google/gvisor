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

package parser

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"gvisor.dev/gvisor/pkg/sentry/devices/nvproxy"
	"gvisor.dev/gvisor/pkg/sentry/devices/nvproxy/nvconf"
)

// Runner is a helper for running the driver_ast_parser on a given set of structs.
type Runner struct {
	// Working directory for the runner.
	dir        string
	parserPath string
	inputPath  string

	nonUVMIoctls []nvproxy.IoctlName
	uvmIoctls    []nvproxy.IoctlName
}

// NewRunner creates a new Runner around a given parser file and a temporary working directory.
func NewRunner(parserPath string) (*Runner, error) {
	// Create a temp directory for the runner.
	dir, err := os.MkdirTemp(os.TempDir(), "run_differ_*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary directory: %w", err)
	}

	return &Runner{
		dir:        dir,
		parserPath: parserPath,
	}, nil
}

// Cleanup removes the working directory for the runner.
func (r *Runner) Cleanup() error {
	return os.RemoveAll(r.dir)
}

// CreateInputFile saves a list of structs for the runner to parse.
func (r *Runner) CreateInputFile(info *nvproxy.DriverABIInfo) error {
	numNonUvm := len(info.FrontendInfos) + len(info.ControlInfos) + len(info.AllocationInfos)
	numUvm := len(info.UvmInfos)
	r.nonUVMIoctls = make([]nvproxy.IoctlName, 0, numNonUvm)
	r.uvmIoctls = make([]nvproxy.IoctlName, 0, numUvm)
	inputJSON := InputJSON{
		Structs:   make([]nvproxy.DriverStructName, 0, numNonUvm+numUvm),
		Constants: make([]nvproxy.IoctlName, 0, numNonUvm+numUvm),
	}

	handleIoctlInfo := func(info nvproxy.IoctlInfo, isUVM bool) {
		if info.Name == "" {
			return
		}
		if isUVM {
			r.uvmIoctls = append(r.uvmIoctls, info.Name)
		} else {
			r.nonUVMIoctls = append(r.nonUVMIoctls, info.Name)
		}
		// Add "GVISOR_" prefix to all constants; see WriteIncludeFile().
		inputJSON.Constants = append(inputJSON.Constants, "GVISOR_"+info.Name)
		for _, structDef := range info.Structs {
			inputJSON.Structs = append(inputJSON.Structs, structDef.Name)
		}
	}
	for _, info := range info.FrontendInfos {
		handleIoctlInfo(info, false)
	}
	for _, info := range info.ControlInfos {
		handleIoctlInfo(info, false)
	}
	for _, info := range info.AllocationInfos {
		handleIoctlInfo(info, false)
	}
	for _, info := range info.UvmInfos {
		handleIoctlInfo(info, true)
	}

	f, err := os.CreateTemp(r.dir, "input_*.json")
	if err != nil {
		return fmt.Errorf("failed to create temporary structs list: %w", err)
	}
	defer f.Close()

	if err := json.NewEncoder(f).Encode(inputJSON); err != nil {
		return fmt.Errorf("failed to write structs list to file: %w", err)
	}

	r.inputPath = f.Name()
	return nil
}

// parseSourceFile runs driver_ast_parser on sourceFile for the structs listed in structsFile,
// and returns the parsed JSON output.
func (r *Runner) parseSourceFile(sourcePath string) (*OutputJSON, error) {
	if r.inputPath == "" {
		return nil, fmt.Errorf("input file not created")
	}

	// Run driver_ast_parser on the source file.
	cmd := exec.Command(r.parserPath, "--input", r.inputPath, sourcePath)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to run driver_ast_parser: %v\n%s", err, stderr.String())
	}

	// Unmarshal the output
	var defs OutputJSON
	if err := json.Unmarshal(out, &defs); err != nil {
		return nil, fmt.Errorf("failed to unmarshal output file: %w", err)
	}

	// Remove the "GVISOR_" prefix from all constants; see WriteIncludeFile().
	constants := make(map[string]uint64)
	for name, value := range defs.Constants {
		constants[strings.TrimPrefix(name, "GVISOR_")] = value
	}
	defs.Constants = constants

	return &defs, nil
}

// runParserConfig runs the driver_ast_parser on the given config options and merges all the
// JSON outputs into a single OutputJSON.
func (r *Runner) runParserConfig(config []ClangASTConfig) (*OutputJSON, error) {
	var allDefs *OutputJSON = nil
	for _, config := range config {
		defs, err := r.parseSourceFile(config.Filename)
		if err != nil {
			return nil, fmt.Errorf("failed to parse source file: %w", err)
		}

		if allDefs == nil {
			allDefs = defs
		} else {
			allDefs.Merge(*defs)
		}
	}
	return allDefs, nil
}

// ParseDriver checks out the git repo for the given version, and runs the driver_ast_parser on the
// source code.
func (r *Runner) ParseDriver(version nvconf.DriverVersion) (*OutputJSON, error) {
	// Create a temp directory to run the parser in.
	// This is needed to set up compile_commands.json, since it needs to be named that exactly.
	dir, err := os.MkdirTemp(r.dir, "run_differ_*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary directory: %w", err)
	}
	defer os.RemoveAll(dir)

	source, err := CloneDriverSource(dir, version)
	if err != nil {
		return nil, fmt.Errorf("failed to clone git repo: %w", err)
	}

	config, err := CreateIncludeFiles(dir, *source, r.nonUVMIoctls, r.uvmIoctls)
	if err != nil {
		return nil, fmt.Errorf("failed to create include files: %w", err)
	}

	if err := CreateCompileCommandsFile(dir, config); err != nil {
		return nil, fmt.Errorf("failed to create compile_commands.json: %w", err)
	}

	defs, err := r.runParserConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to run driver_ast_parser: %w", err)
	}

	return defs, nil
}
