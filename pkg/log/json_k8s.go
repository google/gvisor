// Copyright 2018 The gVisor Authors.
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

package log

import (
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"time"
)

type k8sJSONLog struct {
	Log   string    `json:"log"`
	Level Level     `json:"level"`
	Time  time.Time `json:"time"`
}

// K8sJSONEmitter logs messages in json format that is compatible with
// Kubernetes fluent configuration.
type K8sJSONEmitter struct {
	*Writer
}

// Emit implements Emitter.Emit.
func (e K8sJSONEmitter) Emit(depth int, level Level, timestamp time.Time, format string, v ...any) {
	logLine := fmt.Sprintf(format, v...)
	if _, file, line, ok := runtime.Caller(depth + 1); ok {
		if slash := strings.LastIndexByte(file, byte('/')); slash >= 0 {
			file = file[slash+1:] // Trim any directory path from the file.
		}
		logLine = fmt.Sprintf("%s:%d] %s", file, line, logLine)
	}
	j := k8sJSONLog{
		Log:   logLine,
		Level: level,
		Time:  timestamp,
	}
	b, err := json.Marshal(j)
	if err != nil {
		panic(err)
	}
	e.Writer.Write(b)
}
