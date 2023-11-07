// Copyright 2023 The gVisor Authors.
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

package nvproxy

import (
	"fmt"
)

func (n *nvproxy) afterLoad() {
	Init()
	abiCons, ok := abis[n.version]
	if !ok {
		panic(fmt.Sprintf("driver version %q not found in abis map", n.version))
	}
	n.abi = abiCons.cons()
}
