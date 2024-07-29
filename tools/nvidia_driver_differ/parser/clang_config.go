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
	"encoding/json"
	"fmt"
	"os"
	"path"
)

// ClangASTConfig is the format for compilation_commands.json.
type ClangASTConfig struct {
	Directory string   `json:"directory"`
	Arguments []string `json:"arguments"`
	Filename  string   `json:"file"`
}

// NewParserConfig creates a ClangASTConfig for the given file using the list of includes.
func NewParserConfig(directory, filename string, includes []string) ClangASTConfig {
	args := []string{"clang"}
	for _, include := range includes {
		args = append(args, "-I", include)
	}
	args = append(args, filename)

	return ClangASTConfig{
		Directory: directory,
		Arguments: args,
		Filename:  filename,
	}
}

// CreateCompileCommandsFile creates a new compile_commands.json file in the given directory, and
// writes config to it.
func CreateCompileCommandsFile(dir string, config []ClangASTConfig) error {
	f, err := os.Create(path.Join(dir, "compile_commands.json"))
	if err != nil {
		return fmt.Errorf("failed to create compile_commands.json: %w", err)
	}
	defer f.Close()

	if err := json.NewEncoder(f).Encode(config); err != nil {
		return fmt.Errorf("failed to write config to file: %w", err)
	}

	return nil
}
