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
	"bufio"
	"fmt"
	"io"
	"path/filepath"

	"gvisor.dev/gvisor/pkg/sentry/devices/nvproxy"
)

// DriverSourceDir represents a directory containing the source code for a given driver version.
type DriverSourceDir struct {
	ParentDirectory string
	Version         nvproxy.DriverVersion
}

// Name returns the name of the driver source directory.
func (d DriverSourceDir) Name() string {
	return d.Version.String()
}

// GlobDriverFiles returns all files in the given driver directory that match the given pattern.
func (d *DriverSourceDir) GlobDriverFiles(pattern string) ([]string, error) {
	files, err := filepath.Glob(fmt.Sprintf("%s/%s/%s", d.ParentDirectory, d.Name(), pattern))
	if err != nil {
		return nil, fmt.Errorf("failed to glob files: %w", err)
	}
	return files, nil
}

// GetNonUVMSourcePaths returns the list of paths for non-uvm source files.
func (d *DriverSourceDir) GetNonUVMSourcePaths() ([]string, error) {
	patterns := []string{
		"src/common/sdk/nvidia/inc/nvos.h",
		"src/nvidia/arch/nvalloc/unix/include/nv-ioctl.h",
		"src/nvidia/arch/nvalloc/unix/include/nv-unix-nvos-params-wrappers.h",
		"src/common/sdk/nvidia/inc/class/*.h",
		"src/common/sdk/nvidia/inc/ctrl/*.h",
		"src/common/sdk/nvidia/inc/ctrl/*/*.h",
	}

	sources := []string{}
	for _, pattern := range patterns {
		files, err := d.GlobDriverFiles(pattern)
		if err != nil {
			return nil, fmt.Errorf("failed to glob files: %w", err)
		}
		sources = append(sources, files...)
	}
	return sources, nil
}

// GetUVMSourcePaths returns the list of paths for uvm source files.
func (d *DriverSourceDir) GetUVMSourcePaths() []string {
	return []string{
		fmt.Sprintf("%s/kernel-open/nvidia-uvm/uvm_ioctl.h", d.Name()),
		fmt.Sprintf("%s/kernel-open/nvidia-uvm/uvm_linux_ioctl.h", d.Name()),
	}
}

// GetNonUVMIncludePaths returns the list of paths for non-uvm include files.
func (d *DriverSourceDir) GetNonUVMIncludePaths() []string {
	return []string{
		fmt.Sprintf("%s/src/common/sdk/nvidia/inc", d.Name()),
		fmt.Sprintf("%s/src/common/shared/inc", d.Name()),
		fmt.Sprintf("%s/src/nvidia/arch/nvalloc/unix/include", d.Name()),
	}
}

// GetUVMIncludePaths returns the list of paths for uvm include files.
func (d *DriverSourceDir) GetUVMIncludePaths() []string {
	return []string{
		fmt.Sprintf("%s/kernel-open/common/inc", d.Name()),
	}
}

// WriteIncludeFile writes an cc file at file that includes all the given sources.
func WriteIncludeFile(sources []string, w io.Writer) error {
	bufW := bufio.NewWriter(w)
	for _, source := range sources {
		if _, err := bufW.WriteString(fmt.Sprintf("#include \"%s\"\n", source)); err != nil {
			return fmt.Errorf("failed to write to include file: %w", err)
		}
	}

	return bufW.Flush()
}
