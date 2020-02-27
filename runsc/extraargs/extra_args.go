// Copyright 2020 The gVisor Authors.
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

// Package extraargs holds an object that can hold extra arguments not specified alongside
// the other default args.
package extraargs

// ExtraArgs can be used to hold other miscellaneous arguments not specified
// alongside the other default args. To be used in conjunction with addExtraFiles
// in runsc/sandbox, wherein extra files can be associated with specified flags.
type ExtraArgs struct {
}

// New returns a pointer to a new ExtraArgs object.
func New() *ExtraArgs {
	ea := ExtraArgs{}
	return &ea
}

// Flags returns a string array representation of the arguments defined in ExtraArgs,
// such that they can be passed into a command as flags.
func (e *ExtraArgs) Flags() []string {
	return []string{}
}

// Evaluate is where any final handling of extra arguments should take place,
// in a way similar to arg handling in boot/loader.go.
func (e *ExtraArgs) Evaluate() error {
	return nil
}
