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

// Package cli provides a CLI interface for a mutating Kubernetes webhook.
package cli

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/webhook/pkg/injector"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8snet "k8s.io/apimachinery/pkg/util/net"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var (
	address   = flag.String("address", "", "The ip address the admission webhook serves on. If unspecified, a public address is selected automatically.")
	port      = flag.Int("port", 0, "The port the admission webhook serves on.")
	podLabels = flag.String("pod-namespace-labels", "", "A comma-separated namespace label selector, the admission webhook will only take effect on pods in selected namespaces, e.g. `label1,label2`.")
)

// Main runs the webhook.
func Main() {
	flag.Parse()

	if err := run(); err != nil {
		log.Warningf("%v", err)
		os.Exit(1)
	}
}

func run() error {
	log.Infof("Starting %s\n", injector.Name)

	// Create client config.
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("create in cluster config: %w", err)
	}

	// Create clientset.
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("create kubernetes client: %w", err)
	}

	if err := injector.CreateConfiguration(clientset, parsePodLabels()); err != nil {
		return fmt.Errorf("create webhook configuration: %w", err)
	}

	if err := startWebhookHTTPS(clientset); err != nil {
		return fmt.Errorf("start webhook https server: %w", err)
	}

	return nil
}

func parsePodLabels() *metav1.LabelSelector {
	rv := &metav1.LabelSelector{}
	for _, s := range strings.Split(*podLabels, ",") {
		req := metav1.LabelSelectorRequirement{
			Key:      strings.TrimSpace(s),
			Operator: "Exists",
		}
		rv.MatchExpressions = append(rv.MatchExpressions, req)
	}
	return rv
}

func startWebhookHTTPS(clientset kubernetes.Interface) error {
	log.Infof("Starting HTTPS handler")
	defer log.Infof("Stopping HTTPS handler")

	if *address == "" {
		ip, err := k8snet.ChooseHostInterface()
		if err != nil {
			return fmt.Errorf("select ip address: %w", err)
		}
		*address = ip.String()
	}
	mux := http.NewServeMux()
	mux.Handle("/", http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			injector.Admit(w, r)
		}))
	server := &http.Server{
		// Listen on all addresses.
		Addr:      net.JoinHostPort(*address, strconv.Itoa(*port)),
		TLSConfig: injector.GetTLSConfig(),
		Handler:   mux,
	}
	if err := server.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
		return fmt.Errorf("start HTTPS handler: %w", err)
	}
	return nil
}
