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
	"encoding/gob"
	"encoding/json"
	"fmt"
	"go/token"
	"io"
	"os"
	"reflect"
	"sort"
)

// Finding is a single finding.
type Finding struct {
	Category AnalyzerName
	Position token.Position
	Message  string
}

// findingSize is the size of the finding struct itself.
var findingSize = int64(reflect.TypeOf(Finding{}).Size())

// Size implements worker.Sizer.Size.
func (f *Finding) Size() int64 {
	return int64(len(f.Category)) + int64(len(f.Message)) + findingSize
}

// String implements fmt.Stringer.String.
func (f *Finding) String() string {
	return fmt.Sprintf("%s: %s: %s", f.Category, f.Position.String(), f.Message)
}

// FindingSet is a collection of findings.
type FindingSet []Finding

// Size implmements worker.Sizer.Size.
func (fs FindingSet) Size() int64 {
	size := int64(0)
	for _, finding := range fs {
		size += finding.Size()
	}
	return size
}

// Sort sorts all findings.
func (fs FindingSet) Sort() {
	sort.Slice(fs, func(i, j int) bool {
		switch {
		case fs[i].Position.Filename < fs[j].Position.Filename:
			return true
		case fs[i].Position.Filename > fs[j].Position.Filename:
			return false
		case fs[i].Position.Line < fs[j].Position.Line:
			return true
		case fs[i].Position.Line > fs[j].Position.Line:
			return false
		case fs[i].Position.Column < fs[j].Position.Column:
			return true
		case fs[i].Position.Column > fs[j].Position.Column:
			return false
		case fs[i].Category < fs[j].Category:
			return true
		case fs[i].Category > fs[j].Category:
			return false
		case fs[i].Message < fs[j].Message:
			return true
		case fs[i].Message > fs[j].Message:
			return false
		default:
			return false
		}
	})
}

// WriteFindingsTo serializes findings.
func WriteFindingsTo(w io.Writer, findings FindingSet, asJSON bool) error {
	// N.B. Sort all the findings in order to maximize cacheability.
	findings.Sort()
	if asJSON {
		enc := json.NewEncoder(w)
		return enc.Encode(findings)
	}
	enc := gob.NewEncoder(w)
	return enc.Encode(findings)
}

// ExtractFindingsFromFile loads findings from a file.
func ExtractFindingsFromFile(filename string, asJSON bool) (FindingSet, error) {
	r, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return ExtractFindingsFrom(r, asJSON)
}

// ExtractFindingsFromBytes loads findings from bytes.
func ExtractFindingsFrom(r io.Reader, asJSON bool) (findings FindingSet, err error) {
	if asJSON {
		dec := json.NewDecoder(r)
		err = dec.Decode(&findings)
	} else {
		dec := gob.NewDecoder(r)
		err = dec.Decode(&findings)
	}
	return findings, err
}

func init() {
	gob.Register((*Finding)(nil))
	gob.Register((*FindingSet)(nil))
}
