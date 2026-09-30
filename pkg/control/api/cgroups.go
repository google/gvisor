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

package api

import (
	"fmt"
)

// CgroupControlFile identifies a specific control file within a
// specific cgroup, for the hierarchy with a given controller.
type CgroupControlFile struct {
	Controller string `json:"controller"`
	Path       string `json:"path"`
	Name       string `json:"name"`
}

// CgroupsResult represents the result of a cgroup operation.
type CgroupsResult struct {
	Data    string `json:"value"`
	IsError bool   `json:"is_error"`
}

// AsError interprets the result as an error.
func (r *CgroupsResult) AsError() error {
	if r.IsError {
		return fmt.Errorf("%s", r.Data)
	}
	return nil
}

// Unpack splits CgroupsResult into a (value, error) tuple.
func (r *CgroupsResult) Unpack() (string, error) {
	if r.IsError {
		return "", fmt.Errorf("%s", r.Data)
	}
	return r.Data, nil
}

// CgroupsResults represents the list of results for a batch command.
type CgroupsResults struct {
	Results []CgroupsResult `json:"results"`
}

// CgroupsReadArg represents the arguments for a single read command.
type CgroupsReadArg struct {
	File CgroupControlFile `json:"file"`
}

// CgroupsReadArgs represents the list of arguments for a batched read command.
type CgroupsReadArgs struct {
	Args []CgroupsReadArg `json:"args"`
}

// CgroupsWriteArg represents the arguments for a single write command.
type CgroupsWriteArg struct {
	File  CgroupControlFile `json:"file"`
	Value string            `json:"value"`
}

// CgroupsWriteArgs represents the lust of arguments for a batched write command.
type CgroupsWriteArgs struct {
	Args []CgroupsWriteArg `json:"args"`
}
