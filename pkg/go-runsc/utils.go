/*
Copyright The containerd Authors.
Copyright 2018 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package runsc

import (
	"bytes"
	"strings"
	"sync"
)

var bytesBufferPool = sync.Pool{
	New: func() interface{} {
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

// FormatLogPath parses runsc config, and fill in %ID% in the log path.
// * For debug-log, it fills in the id in place;
// * For user-log, it fills in the id, returns the user log path, and deletes
// the `user-log` entry from the config, because it will only be added to runsc
// calls that create a new sandbox.
func FormatLogPath(id string, config map[string]string) string {
	if path, ok := config["debug-log"]; ok {
		config["debug-log"] = strings.Replace(path, "%ID%", id, -1)
	}
	var userLog string
	if path, ok := config["user-log"]; ok {
		userLog = strings.Replace(path, "%ID%", id, -1)
		delete(config, "user-log")
	}
	return userLog
}
