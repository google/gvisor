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

package lib

import (
	"flag"
	"os"
	"testing"
)

var excludeFile = flag.String("exclude_file", "", "file to test (standard format)")

func TestMain(m *testing.M) {
	flag.Parse()
	os.Exit(m.Run())
}

// Test that the exclude file parses without error.
func TestExcludelist(t *testing.T) {
	_, err := ExcludeFilter(*excludeFile)
	if err != nil {
		t.Fatalf("error parsing exclude file: %v", err)
	}
}
