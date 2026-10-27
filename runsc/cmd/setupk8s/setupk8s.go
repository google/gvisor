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

// Package setupk8s installs the gVisor Helm chart.
package setupk8s

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/google/subcommands"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/version"
)

// Command implements the setup-k8s command.
type Command struct {
	chart        string
	chartVersion string
	values       string
	kubeContext  string
	namespace    string
	releaseName  string
	timeout      time.Duration
}

// Name implements subcommands.Command.
func (*Command) Name() string { return "setup-k8s" }

// Synopsis implements subcommands.Command.
func (*Command) Synopsis() string { return "installs gVisor on Kubernetes nodes using Helm" }

// Usage implements subcommands.Command.
func (*Command) Usage() string {
	return `setup-k8s --chart=<chart reference or local path> [flags]

Requires Helm 3 or 4 and kubectl in PATH. Uses the current context unless overridden.
The chart configures containerd on selected nodes and can restart it.
Use --values to select nodes and configure the installation.
`
}

// SetFlags implements subcommands.Command.
func (c *Command) SetFlags(f *flag.FlagSet) {
	f.StringVar(&c.chart, "chart", "", "Helm chart reference or local chart path")
	f.StringVar(&c.chartVersion, "chart-version", "", "chart version (defaults to this runsc release)")
	f.StringVar(&c.values, "values", "", "Helm values file")
	f.StringVar(&c.kubeContext, "kube-context", os.Getenv("HELM_KUBECONTEXT"), "Kubernetes context (defaults to Helm's current context)")
	f.StringVar(&c.namespace, "namespace", "kube-system", "installer namespace")
	f.StringVar(&c.releaseName, "release-name", "gvisor", "Helm release name")
	f.DurationVar(&c.timeout, "timeout", 10*time.Minute, "time to wait for installation")
}

// FetchSpec implements util.SubCommand.
func (*Command) FetchSpec(*config.Config, *flag.FlagSet) (string, *specs.Spec, error) {
	return "", nil, nil
}

// Execute implements subcommands.Command.
func (c *Command) Execute(ctx context.Context, f *flag.FlagSet, _ ...any) subcommands.ExitStatus {
	if f.NArg() != 0 {
		return util.Errorf("setup-k8s does not accept positional arguments")
	}
	args, err := c.arguments(version.Version())
	if err != nil {
		return util.Errorf("setup-k8s: %v", err)
	}
	helm, err := exec.LookPath("helm")
	if err != nil {
		return util.Errorf("setup-k8s requires Helm in PATH: %v", err)
	}
	kubectl, err := exec.LookPath("kubectl")
	if err != nil {
		return util.Errorf("setup-k8s requires kubectl in PATH: %v", err)
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	if status := runCommand(ctx, helm, args); status != subcommands.ExitSuccess {
		return status
	}
	// Helm 3 permits maxUnavailable unready DaemonSet pods even with --wait.
	return runCommand(ctx, kubectl, c.rolloutArguments())
}

func runCommand(ctx context.Context, executable string, args []string) subcommands.ExitStatus {
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() > 0 {
			return subcommands.ExitStatus(exitErr.ExitCode())
		}
		return util.Errorf("running %s: %v", executable, err)
	}
	return subcommands.ExitSuccess
}

func (c *Command) arguments(runscVersion string) ([]string, error) {
	// Both tools must use the same kubeconfig credentials and API server.
	for _, name := range []string{"HELM_KUBETOKEN", "HELM_KUBEASUSER", "HELM_KUBEASGROUPS", "HELM_KUBEAPISERVER", "HELM_KUBECAFILE", "HELM_KUBETLS_SERVER_NAME", "HELM_KUBEINSECURE_SKIP_TLS_VERIFY"} {
		if os.Getenv(name) != "" {
			return nil, fmt.Errorf("%s is not supported by setup-k8s: configure it in KUBECONFIG so Helm and kubectl use the same connection", name)
		}
	}
	if c.chart == "" || strings.HasPrefix(c.chart, "-") {
		return nil, fmt.Errorf("--chart must name a chart reference or local path")
	}
	if c.releaseName == "" || strings.HasPrefix(c.releaseName, "-") || c.namespace == "" || c.timeout <= 0 {
		return nil, fmt.Errorf("release name, namespace and a positive timeout are required")
	}
	chartVersion := c.chartVersion
	if _, err := os.Stat(c.chart); err != nil && chartVersion == "" {
		var err error
		chartVersion, err = releaseChartVersion(runscVersion)
		if err != nil {
			return nil, fmt.Errorf("%w: use --chart-version or a local chart", err)
		}
	}
	args := []string{"upgrade", "--install", c.releaseName, c.chart,
		"--namespace", c.namespace, "--create-namespace", "--wait", "--timeout", c.timeout.String()}
	for _, option := range [][2]string{{"--version", chartVersion}, {"--values", c.values}, {"--kube-context", c.kubeContext}} {
		if option[1] != "" {
			args = append(args, option[0], option[1])
		}
	}
	return args, nil
}

func (c *Command) rolloutArguments() []string {
	args := []string{"rollout", "status", "daemonset/" + c.releaseName + "-gvisor",
		"--namespace", c.namespace, "--timeout", c.timeout.String()}
	if c.kubeContext != "" {
		args = append(args, "--context", c.kubeContext)
	}
	return args
}

func releaseChartVersion(v string) (string, error) {
	release, ok := strings.CutPrefix(v, "release-")
	if !ok {
		return "", fmt.Errorf("runsc version %q is not a tagged release", v)
	}
	date, patch, havePatch := strings.Cut(release, ".")
	if !havePatch {
		patch = "0"
	}
	if _, err := time.Parse("20060102", date); err != nil || !strings.HasPrefix(date, "20") {
		return "", fmt.Errorf("invalid release date in %q", v)
	}
	n, err := strconv.ParseUint(patch, 10, 32)
	if err != nil || strconv.FormatUint(n, 10) != patch {
		return "", fmt.Errorf("invalid release revision in %q", v)
	}
	return date + "." + patch + ".0", nil
}
