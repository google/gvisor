// Copyright 2021 The gVisor Authors.
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

// Package mitigate provides libraries for the mitigate command. The
// mitigate command mitigates side channel attacks such as MDS. Mitigate
// shuts down CPUs via /sys/devices/system/cpu/cpu{N}/online. In addition,
// the mitigate also handles computing available CPU in kubernetes kube_config
// files.
package mitigate
