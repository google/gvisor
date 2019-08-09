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

package common_test

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"gvisor.dev/gvisor/runsc/test/testutil"
	"gvisor.dev/gvisor/test/runtimes/common"
)

func touch(t *testing.T, name string) {
	t.Helper()
	f, err := os.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSearchEmptyDir(t *testing.T) {
	td, err := ioutil.TempDir(testutil.TmpDir(), "searchtest")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(td)

	var want []string

	testFilter := regexp.MustCompile(`^test-[^-].+\.tc$`)
	got, err := common.Search(td, testFilter)
	if err != nil {
		t.Errorf("Search error: %v", err)
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("Found %#v; want %#v", got, want)
	}
}

func TestSearch(t *testing.T) {
	td, err := ioutil.TempDir(testutil.TmpDir(), "searchtest")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(td)

	// Creating various files similar to the test filter regex.
	files := []string{
		"emp/",
		"tee/",
		"test-foo.tc",
		"test-foo.tc",
		"test-bar.tc",
		"test-sam.tc",
		"Test-que.tc",
		"test-brett",
		"test--abc.tc",
		"test---xyz.tc",
		"test-bool.TC",
		"--test-gvs.tc",
		" test-pew.tc",
		"dir/test_baz.tc",
		"dir/testsnap.tc",
		"dir/test-luk.tc",
		"dir/nest/test-ok.tc",
		"dir/dip/diz/goog/test-pack.tc",
		"dir/dip/diz/wobble/thud/test-cas.e",
		"dir/dip/diz/wobble/thud/test-cas.tc",
	}
	want := []string{
		"dir/dip/diz/goog/test-pack.tc",
		"dir/dip/diz/wobble/thud/test-cas.tc",
		"dir/nest/test-ok.tc",
		"dir/test-luk.tc",
		"test-bar.tc",
		"test-foo.tc",
		"test-sam.tc",
	}

	for _, item := range files {
		if strings.HasSuffix(item, "/") {
			// This item is a directory, create it.
			if err := os.MkdirAll(filepath.Join(td, item), 0755); err != nil {
				t.Fatal(err)
			}
		} else {
			// This item is a file, create the directory and touch file.
			// Create directory in which file should be created
			fullDirPath := filepath.Join(td, filepath.Dir(item))
			if err := os.MkdirAll(fullDirPath, 0755); err != nil {
				t.Fatal(err)
			}
			// Create file with full path to file.
			touch(t, filepath.Join(td, item))
		}
	}

	testFilter := regexp.MustCompile(`^test-[^-].+\.tc$`)
	got, err := common.Search(td, testFilter)
	if err != nil {
		t.Errorf("Search error: %v", err)
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("Found %#v; want %#v", got, want)
	}
}
