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

// Package install provides a function to install gVisor in a k8s cluster.
package install

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/subcommands"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/tools/gvisor_k8s_tool/cluster"
	"gvisor.dev/gvisor/tools/gvisor_k8s_tool/provider/clusterflag"
	"gvisor.dev/gvisor/tools/gvisor_k8s_tool/spec"
)

// Install installs runsc from the given image in the given cluster.
func Install(ctx context.Context, c *cluster.Cluster, image string, options spec.InstallOptions) error {
	ds := spec.RunscInstallDaemonSet(image, options)
	// Delete a daemonset of the same name in the same namespace in case there is a collision.
	if err := c.DeleteDaemonset(ctx, ds); err != nil && !strings.Contains(err.Error(), "not found") {
		return fmt.Errorf("failed to delete DaemonSet %q in namespace %q: %w", ds.Name, ds.Namespace, err)
	}

	// Create the daemonset, but don't delete it so that we can get logs if there
	// is a problem.
	log.Infof("Creating DaemonSet %q in namespace %q...", ds.Name, ds.Namespace)
	ds, err := c.CreateDaemonset(ctx, ds)
	if err != nil {
		return fmt.Errorf("failed to create DaemonSet %q in namespace %q: %w", ds.Name, ds.Namespace, err)
	}

	log.Infof("Waiting for DaemonSet %q in namespace %q...", ds.Name, ds.Namespace)
	if err := c.WaitForDaemonset(ctx, ds); err != nil {
		return fmt.Errorf("failed to wait for daemonset: %v", err)
	}

	log.Infof("DaemonSet %q in namespace %q complete.", ds.Name, ds.Namespace)
	return nil
}

// Command implements subcommands.Command.
type Command struct {
	Image               string
	Cluster             clusterflag.Flag
	DaemonSetName       string
	DaemonSetNamespace  string
	PauseContainerImage string
}

// Name implements subcommands.Command.Name.
func (*Command) Name() string {
	return "install"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*Command) Synopsis() string {
	return "install gVisor in a kubernetes cluster"
}

// Usage implements subcommands.Command.Usage.
func (*Command) Usage() string {
	return `install --image=<image> --cluster=<cluster_info>

Where "<image>" is the name of the runsc installer image,
and <cluster_info> contains information on how to connect
to the Kubernetes cluster to install to.

<cluster_info> can take the form of:
  * --cluster=kube:<context_name>
      ... where "<context_name>" is the name of a context in the
      kubectl config file at $KUBECONFIG.
      If $KUBECONFIG is not defined, it defaults to
      $HOME/.kube/config.
      If the context_name is empty, the default ("current")
      context in the config file is used.
  * --cluster=gke:projects/<project>/locations/<location>/clusters/<cluster>
      ... where <project>, <location> and <cluster> identify the project,
      location, and name of the Google Kubernetes Engine cluster.

`
}

// SetFlags implements subcommands.Command.SetFlags.
func (c *Command) SetFlags(f *flag.FlagSet) {
	f.StringVar(&c.Image, "image", "", "runsc installer image")
	f.Var(&c.Cluster, "cluster", "Kubernetes cluster to install runsc into")
	f.StringVar(&c.DaemonSetName, "daemonset-name", "gvisor-runsc-installer", "name of the runsc installer DaemonSet; any previously-existing DaemonSet under this name will be deleted")
	f.StringVar(&c.DaemonSetNamespace, "daemonset-namespace", spec.SystemNamespace, "namespace of the runsc installer DaemonSet")
	f.StringVar(&c.PauseContainerImage, "pause-container-image", spec.PauseContainerImage, "container image that does nothing, used as placeholder in the DaemonSet")
}

// Execute implements subcommands.Command.Execute.
// It installs gVisor in a Kubernetes cluster.
func (c *Command) Execute(ctx context.Context, f *flag.FlagSet, _ ...any) subcommands.ExitStatus {
	if err := c.Cluster.Valid(); err != nil {
		f.Usage()
		return subcommands.ExitUsageError
	}
	clusterClient, err := c.Cluster.Cluster(ctx)
	if err != nil {
		util.Fatalf("Cannot initialize cluster client: %v", err)
	}
	var labels map[string]string
	var nodeSelector map[string]string
	switch c.Cluster.Provider {
	case clusterflag.GKE:
		labels = spec.GKESandboxNodeSelector
		nodeSelector = spec.GKESandboxNodeSelector
	default:
	}
	if err := Install(ctx, clusterClient, c.Image, spec.InstallOptions{
		DaemonSetName:       c.DaemonSetName,
		DaemonSetNamespace:  c.DaemonSetNamespace,
		PauseContainerImage: c.PauseContainerImage,
		Labels:              labels,
		NodeSelector:        nodeSelector,
	}); err != nil {
		util.Fatalf("Install failed: %v", err)
	}
	return subcommands.ExitSuccess
}
