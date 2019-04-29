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

// +build linux

package syserr

import (
	"fmt"
	"syscall"
)

const maxErrno = 134

type linuxHostTranslation struct {
	err *Error
	ok  bool
}

var linuxHostTranslations [maxErrno]linuxHostTranslation

// FromHost translates a syscall.Errno to a corresponding Error value.
func FromHost(err syscall.Errno) *Error {
	if err < 0 || int(err) >= len(linuxHostTranslations) || !linuxHostTranslations[err].ok {
		panic(fmt.Sprintf("unknown host errno %q (%d)", err.Error(), err))
	}
	return linuxHostTranslations[err].err
}

func addLinuxHostTranslation(host syscall.Errno, trans *Error) {
	if linuxHostTranslations[host].ok {
		panic(fmt.Sprintf("duplicate translation for host errno %q (%d)", host.Error(), host))
	}
	linuxHostTranslations[host] = linuxHostTranslation{err: trans, ok: true}
}
