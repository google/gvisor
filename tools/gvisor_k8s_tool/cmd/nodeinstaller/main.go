// Copyright The Isola Authors
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

// Command nodeinstaller installs the bundled gVisor runtime on its host node.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/tools/gvisor_k8s_tool/installer"
)

type logger struct{}

func (logger) Info(message string, fields ...any) { log.Infof("%s %v", message, fields) }
func (logger) Warn(message string, fields ...any) {
	log.Warningf("%s %v", message, fields)
}
func (logger) Error(message string, fields ...any) {
	log.Warningf("%s %v", message, fields)
}

func main() {
	cfg, err := installer.ConfigFromEnv()
	if err != nil {
		log.Warningf("invalid configuration: %v", err)
		os.Exit(1)
	}
	restCfg, err := rest.InClusterConfig()
	if err != nil {
		log.Warningf("loading Kubernetes configuration: %v", err)
		os.Exit(1)
	}
	clientset, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		log.Warningf("creating Kubernetes client: %v", err)
		os.Exit(1)
	}
	logger := logger{}
	instance := installer.New(cfg, logger, installer.NewNsenterExec(), installer.NewCRIClient(cfg.CRISocketPath()), installer.NewNodeClient(clientset, cfg, logger))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go installer.ServeHealth(ctx, cfg.HealthAddr, instance, logger)
	instance.Run(ctx)
}
