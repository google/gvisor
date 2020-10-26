// Copyright 2019 The gVisor Authors.
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

package nogo

import (
	"encoding/json"
	"fmt"
	"go/token"
	"io/ioutil"
)

// Finding is a single finding.
type Finding struct {
	Category AnalyzerName
	Position token.Position
	Message  string
}

// String implements fmt.Stringer.String.
func (f *Finding) String() string {
	return fmt.Sprintf("%s: %s: %s", f.Category, f.Position.String(), f.Message)
}

// WriteFindingsToFile writes findings to a file.
func WriteFindingsToFile(findings []Finding, filename string) error {
	content, err := WriteFindingsToBytes(findings)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filename, content, 0644)
}

// WriteFindingsToBytes serializes findings as bytes.
func WriteFindingsToBytes(findings []Finding) ([]byte, error) {
	return json.Marshal(findings)
}

// ExtractFindingsFromFile loads findings from a file.
func ExtractFindingsFromFile(filename string) ([]Finding, error) {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return ExtractFindingsFromBytes(content)
}

// ExtractFindingsFromBytes loads findings from bytes.
func ExtractFindingsFromBytes(content []byte) (findings []Finding, err error) {
	err = json.Unmarshal(content, &findings)
	return findings, err
}
