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

package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/google/subcommands"
	"gvisor.googlesource.com/gvisor/pkg/log"
)

// ErrorLogger is where error messages should be written to. These messages are
// consumed by containerd and show up to users of command line tools,
// like docker/kubectl.
var ErrorLogger io.Writer

type jsonError struct {
	Msg   string    `json:"msg"`
	Level string    `json:"level"`
	Time  time.Time `json:"time"`
}

// Errorf logs error to containerd log (--log), to stderr, and debug logs. It
// returns subcommands.ExitFailure for convenience with subcommand.Execute()
// methods:
//    return Errorf("Danger! Danger!")
//
func Errorf(format string, args ...interface{}) subcommands.ExitStatus {
	// If runsc is being invoked by docker or cri-o, then we might not have
	// access to stderr, so we log a serious-looking warning in addition to
	// writing to stderr.
	log.Warningf("FATAL ERROR: "+format, args...)
	fmt.Fprintf(os.Stderr, format+"\n", args...)

	j := jsonError{
		Msg:   fmt.Sprintf(format, args...),
		Level: "error",
		Time:  time.Now(),
	}
	b, err := json.Marshal(j)
	if err != nil {
		panic(err)
	}
	if ErrorLogger != nil {
		ErrorLogger.Write(b)
	}

	return subcommands.ExitFailure
}

// Fatalf logs the same way as Errorf() does, plus *exits* the process.
func Fatalf(format string, args ...interface{}) {
	Errorf(format, args...)
	// Return an error that is unlikely to be used by the application.
	os.Exit(128)
}
