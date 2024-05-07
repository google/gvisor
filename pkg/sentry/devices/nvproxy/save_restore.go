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

//go:build !false
// +build !false

package nvproxy

import (
	goContext "context"
	"fmt"
)

// beforeSave is invoked by stateify.
func (nvp *nvproxy) beforeSave() {
	nvp.objsLock()
	defer nvp.objsUnlock()
	if len(nvp.clients) != 0 {
		panic("can't save with live nvproxy clients")
	}
}

// afterLoad is invoked by stateify.
func (nvp *nvproxy) afterLoad(goContext.Context) {
	Init()
	abiCons, ok := abis[nvp.version]
	if !ok {
		panic(fmt.Sprintf("driver version %q not found in abis map", nvp.version))
	}
	nvp.abi = abiCons.cons()
	nvp.objsFreeSet = make(map[*object]struct{})
}

// beforeSave is invoked by stateify.
func (fd *frontendFD) beforeSave() {
	panic("nvproxy.frontendFD is not saveable.")
}

// beforeSave is invoked by stateify.
func (fd *uvmFD) beforeSave() {
	panic("nvproxy.uvmFD is not saveable.")
}
