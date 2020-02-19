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

package boot

import (
	"gvisor.dev/gvisor/runsc/flag"
)

// ExtraArgs can be used to hold other miscellaneous arguments not specified
// within the normal boot process. To be used in conjunction with addExtraFiles
// in runsc/sandbox, wherein extra files can be associated with specified flags.
type ExtraArgs struct {
}

// SetFromFlags may be used to accept arguments and store their values in
// fields defined in ExtraArgs, similar to SetFlags in cmd/boot.go. The args
// should be only be set here, and should be handled in evaluate().
func (e *ExtraArgs) SetFromFlags(f *flag.FlagSet) {
}

// evaluate is where any final handling of extra arguments should take place,
// in a way similar to arg handling in boot/loader.go.
func (e *ExtraArgs) evaluate() error {
	return nil
}
