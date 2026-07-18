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

// This file is used in non-fastbuild builds, which embed a copy of the metric
// server binary. The fastbuild variant (embed_metricserver_elided.go) elides
// the embedded copy to keep fastbuild binaries small; see the BUILD file.

package embed

import (
	"gvisor.dev/gvisor/runsc/cmd/metricserver"
	"gvisor.dev/gvisor/runsc/gvisorbinaries"
)

func init() {
	gvisorbinaries.MetricServer.DeclareEmbedded(func(o gvisorbinaries.Options) error {
		return metricserver.Exec(metricserver.Options{Argv: o.Argv, Envv: o.Envv})
	}, func(o gvisorbinaries.Options) (int, error) {
		return metricserver.ForkExec(metricserver.Options{
			Argv:        o.Argv,
			Envv:        o.Envv,
			Files:       o.Files,
			SysProcAttr: o.SysProcAttr,
		})
	})
}
