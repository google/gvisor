// Copyright 2026 The gVisor Authors.
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

// Package embed wires the embedded (compiled-into-runsc) fallbacks for the
// gvisorbinaries sidecar binaries. It is imported for its side effects by the
// runsc binary's entrypoint (runsc/cli/maincli)
//
// Each sidecar is registered in a per-sidecar file that the BUILD rule swaps
// for an empty variant when the embedded copy is elided; building with
// `--define gvisor_embed_sidecars=false` elides all of them, for installations
// that ship on-disk sidecar binaries and don't want runsc to carry embedded
// copies.
//
// TODO(gvisor.dev/issue/13718): embedded sidecar binaries are being replaced by
// on-disk binaries in a "gvisor-bin/" directory. Once the embedded copies are
// removed, delete this package.
package embed
