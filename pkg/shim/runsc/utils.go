// Copyright 2018 The containerd Authors.
// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package runsc

import (
	"bytes"
	"strings"
	"sync"
)

var bytesBufferPool = sync.Pool{
	New: func() any {
		return bytes.NewBuffer(nil)
	},
}

func getBuf() *bytes.Buffer {
	return bytesBufferPool.Get().(*bytes.Buffer)
}

func putBuf(b *bytes.Buffer) {
	b.Reset()
	bytesBufferPool.Put(b)
}

// pathLikeFlags are runsc flags which refer to paths to files.
var pathLikeFlags = []string{
	"log",
	"panic-log",
	"debug-log",
	"coverage-report",
	"profile-block",
	"profile-cpu",
	"profile-heap",
	"profile-mutex",
	"trace",
}

// replaceID replaces %ID% in `path` with the given sandbox ID.
func replaceID(id string, path string) string {
	return strings.Replace(path, "%ID%", id, -1)
}

// EmittedPaths returns a list of file paths that the sandbox may need to
// create using the given configuration. Useful to create parent directories.
func EmittedPaths(id string, config map[string]string) []string {
	var paths []string
	for _, cfgFlag := range pathLikeFlags {
		if path, ok := config[cfgFlag]; ok {
			paths = append(paths, replaceID(id, path))
		}
	}
	return paths
}

// FormatRunscPaths fills in %ID% in path-like flags.
func FormatRunscPaths(id string, config map[string]string) {
	for _, cfgFlag := range pathLikeFlags {
		if path, ok := config[cfgFlag]; ok {
			config[cfgFlag] = replaceID(id, path)
		}
	}
}

// FormatShimLogPath creates the file path to the log file. It replaces %ID%
// in the path with the provided "id". It also uses a default log name if the
// path ends with '/'.
func FormatShimLogPath(path string, id string) string {
	if strings.HasSuffix(path, "/") {
		// Default format: <path>/runsc-shim-<ID>.log
		path += "runsc-shim-%ID%.log"
	}
	return replaceID(id, path)
}
