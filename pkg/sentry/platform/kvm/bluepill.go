// Copyright 2018 Google LLC
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

package kvm

import (
	"fmt"
	"reflect"
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/sentry/platform/safecopy"
)

// bluepill enters guest mode.
func bluepill(*vCPU)

// sighandler is the signal entry point.
func sighandler()

// savedHandler is a pointer to the previous handler.
//
// This is called by bluepillHandler.
var savedHandler uintptr

func init() {
	// Install the handler.
	if err := safecopy.ReplaceSignalHandler(syscall.SIGSEGV, reflect.ValueOf(sighandler).Pointer(), &savedHandler); err != nil {
		panic(fmt.Sprintf("Unable to set handler for signal %d: %v", syscall.SIGSEGV, err))
	}
}
