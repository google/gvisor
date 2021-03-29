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

package vfs

import (
	"strings"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/hostarch"
)

// GenericParseMountOptions parses a comma-separated list of options of the
// form "key" or "key=value", where neither key nor value contain commas, and
// returns it as a map. If str contains duplicate keys, then the last value
// wins. For example:
//
// str = "key0=value0,key1,key2=value2,key0=value3" -> map{'key0':'value3','key1':'','key2':'value2'}
//
// GenericParseMountOptions is not appropriate if values may contain commas,
// e.g. in the case of the mpol mount option for tmpfs(5).
func GenericParseMountOptions(str string) map[string]string {
	m := make(map[string]string)
	for _, opt := range strings.Split(str, ",") {
		if len(opt) > 0 {
			res := strings.SplitN(opt, "=", 2)
			if len(res) == 2 {
				m[res[0]] = res[1]
			} else {
				m[opt] = ""
			}
		}
	}
	return m
}

// GenericStatFS returns a statfs struct filled with the common fields for a
// general filesystem. This is analogous to Linux's fs/libfs.cs:simple_statfs().
func GenericStatFS(fsMagic uint64) linux.Statfs {
	return linux.Statfs{
		Type:       fsMagic,
		BlockSize:  hostarch.PageSize,
		NameLength: linux.NAME_MAX,
	}
}
