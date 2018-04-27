// Copyright 2018 Google Inc.
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

package syserr

import (
	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
)

var linuxABITranslations = map[*Error]*linux.Errno{}

// ToLinux translates an Error to a corresponding *linux.Errno value.
func ToLinux(err *Error) *linux.Errno {
	le, ok := linuxABITranslations[err]
	if !ok {
		panic("No Linux ABI translation available for " + err.String())
	}
	return le
}
