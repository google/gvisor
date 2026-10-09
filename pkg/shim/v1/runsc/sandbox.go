// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package runsc

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	goruntime "runtime"
	"strconv"
	"strings"
	"time"

	api "github.com/containerd/containerd/api/runtime/sandbox/v1"
	apitypes "github.com/containerd/containerd/api/types"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/containerd/v2/pkg/protobuf"
	"github.com/containerd/errdefs"
	errgrpc "github.com/containerd/errdefs/pkg/errgrpc"
	"github.com/containerd/log"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"gvisor.dev/gvisor/pkg/shim/v1/proc"
	"gvisor.dev/gvisor/pkg/shim/v1/runsccmd"
	"gvisor.dev/gvisor/pkg/shim/v1/utils"
	"gvisor.dev/gvisor/runsc/specutils"
)

// CRI annotations that containerd puts on the pause container's spec. They
// live in containerd's internal tree, so they cannot be imported.
const (
	sandboxNameAnnotation      = "io.kubernetes.cri.sandbox-name"
	sandboxNamespaceAnnotation = "io.kubernetes.cri.sandbox-namespace"
	sandboxUIDAnnotation       = "io.kubernetes.cri.sandbox-uid"
	sandboxLogDirAnnotation    = "io.kubernetes.cri.sandbox-log-directory"
	sandboxCPUPeriodAnnotation = "io.kubernetes.cri.sandbox-cpu-period"
	sandboxCPUQuotaAnnotation  = "io.kubernetes.cri.sandbox-cpu-quota"
	sandboxCPUSharesAnnotation = "io.kubernetes.cri.sandbox-cpu-shares"
	sandboxMemAnnotation       = "io.kubernetes.cri.sandbox-mem"
)

// gvisorAnnotationPrefix prefixes the annotations that configure runsc.
const gvisorAnnotationPrefix = "dev.gvisor."

// defaultStopTimeout bounds StopSandbox when containerd gives no timeout.
const defaultStopTimeout = 10 * time.Second

// sandboxState is a sandbox created through the sandbox API.
type sandboxState struct {
	id        string
	bundle    string
	container *Container
	createdAt time.Time

	// started is set once StartSandbox has booted the sentry.
	started bool
}

// task returns the process tracking the `runsc create`/`runsc start` pair that
// booted the sandbox. There is no init process inside it.
func (sb *sandboxState) task() *proc.Init {
	return sb.container.task
}

// getSandbox returns the sandbox with the given id.
func (s *runscService) getSandbox(id string) (*sandboxState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sandbox == nil || s.sandbox.id != id {
		return nil, errgrpc.ToGRPCf(errdefs.ErrNotFound, "sandbox %q not created", id)
	}
	return s.sandbox, nil
}

// CreateSandbox implements api.TTRPCSandboxService.CreateSandbox.
func (s *runscService) CreateSandbox(ctx context.Context, req *api.CreateSandboxRequest) (*api.CreateSandboxResponse, error) {
	log.L.Debugf("CreateSandbox, id: %s, bundle: %s", req.SandboxID, req.BundlePath)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sandbox != nil {
		return nil, errgrpc.ToGRPCf(errdefs.ErrAlreadyExists, "shim already serves sandbox %q", s.sandbox.id)
	}

	// containerd writes config.json only if the client set Sandbox.Spec, which
	// CRI does not. Without one, build the spec from the pod config.
	if _, err := os.Stat(filepath.Join(req.BundlePath, "config.json")); os.IsNotExist(err) {
		config := &podSandboxConfig{}
		if req.Options != nil {
			var err error
			if config, err = unmarshalPodSandboxConfig(req.Options); err != nil {
				return nil, err
			}
		}
		spec := sandboxSpec(req.SandboxID, req.NetnsPath, req.Annotations, config)
		if err := utils.WriteSpec(req.BundlePath, spec); err != nil {
			return nil, fmt.Errorf("write sandbox spec: %w", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("stat sandbox spec: %w", err)
	}

	c, err := NewContainer(ctx, s.platform, &ContainerConfig{
		ID:              req.SandboxID,
		Bundle:          req.BundlePath,
		Rootfs:          req.Rootfs,
		Options:         runtimeOptions(req.BundlePath),
		NoRootContainer: true,
	})
	if err != nil {
		// containerd follows a failed CreateSandbox with ShutdownSandbox only,
		// so nothing else removes what `runsc create` may have left behind.
		forceDeleteFromBundle(ctx, req.BundlePath, req.SandboxID)
		return nil, err
	}
	s.sandbox = &sandboxState{
		id:        req.SandboxID,
		bundle:    req.BundlePath,
		container: c,
		createdAt: time.Now(),
	}

	// Version queries report the runsc that runs the sandbox.
	command := c.task.Runtime().Command
	s.versionCommand.Store(&command)

	return &api.CreateSandboxResponse{}, nil
}

// StartSandbox implements api.TTRPCSandboxService.StartSandbox.
func (s *runscService) StartSandbox(ctx context.Context, req *api.StartSandboxRequest) (*api.StartSandboxResponse, error) {
	log.L.Debugf("StartSandbox, id: %s", req.SandboxID)

	sb, err := s.getSandbox(req.SandboxID)
	if err != nil {
		return nil, err
	}
	if err := sb.task().Start(ctx); err != nil {
		return nil, errgrpc.ToGRPC(err)
	}

	s.mu.Lock()
	sb.started = true
	s.mu.Unlock()

	return &api.StartSandboxResponse{
		Pid:       uint32(sb.task().Pid()),
		CreatedAt: protobuf.ToTimestamp(sb.createdAt),
	}, nil
}

// Platform implements api.TTRPCSandboxService.Platform.
func (s *runscService) Platform(ctx context.Context, req *api.PlatformRequest) (*api.PlatformResponse, error) {
	log.L.Debugf("Platform, id: %s", req.SandboxID)

	return &api.PlatformResponse{
		Platform: &apitypes.Platform{
			OS:           goruntime.GOOS,
			Architecture: goruntime.GOARCH,
		},
	}, nil
}

// StopSandbox implements api.TTRPCSandboxService.StopSandbox.
//
// The sandbox has no root process to signal (`runsc kill` refuses it), so it is
// stopped with `runsc delete`. req.TimeoutSecs only bounds the wait for the
// exit: CRI has already stopped the pod's containers with their own grace
// periods.
func (s *runscService) StopSandbox(ctx context.Context, req *api.StopSandboxRequest) (*api.StopSandboxResponse, error) {
	log.L.Debugf("StopSandbox, id: %s", req.SandboxID)

	sb, err := s.getSandbox(req.SandboxID)
	if err != nil {
		return nil, err
	}
	p := sb.task()

	// Without --force, runsc only deletes the sandbox if none of its
	// containers is running. CRI stops them first; anyone else gets them
	// killed.
	if err := p.Runtime().Delete(ctx, sb.id, nil); err != nil {
		log.L.Infof("Deleting sandbox %q without --force failed, forcing: %v", sb.id, err)
		if err := p.Runtime().Delete(ctx, sb.id, &runsccmd.DeleteOpts{Force: true}); err != nil {
			return nil, errgrpc.ToGRPC(fmt.Errorf("destroy sandbox %q: %w", sb.id, err))
		}
	}

	s.mu.Lock()
	started := sb.started
	s.mu.Unlock()
	if !started {
		// No `runsc wait` is running to report an exit.
		p.SetExited(0)
		return &api.StopSandboxResponse{}, nil
	}

	timeout := defaultStopTimeout
	if req.TimeoutSecs > 0 {
		timeout = time.Duration(req.TimeoutSecs) * time.Second
	}
	exited := make(chan struct{})
	go func() {
		p.Wait()
		close(exited)
	}()
	select {
	case <-exited:
	case <-time.After(timeout):
		// The sandbox is deleted; record the exit so WaitSandbox returns.
		log.L.Warningf("Sandbox %q did not report its exit within %v", sb.id, timeout)
		p.SetExited(0)
	}
	return &api.StopSandboxResponse{}, nil
}

// WaitSandbox implements api.TTRPCSandboxService.WaitSandbox.
func (s *runscService) WaitSandbox(ctx context.Context, req *api.WaitSandboxRequest) (*api.WaitSandboxResponse, error) {
	log.L.Debugf("WaitSandbox, id: %s", req.SandboxID)

	sb, err := s.getSandbox(req.SandboxID)
	if err != nil {
		return nil, err
	}
	p := sb.task()
	p.Wait()

	return &api.WaitSandboxResponse{
		ExitStatus: uint32(p.ExitStatus()),
		ExitedAt:   protobuf.ToTimestamp(p.ExitedAt()),
	}, nil
}

// SandboxStatus implements api.TTRPCSandboxService.SandboxStatus.
func (s *runscService) SandboxStatus(ctx context.Context, req *api.SandboxStatusRequest) (*api.SandboxStatusResponse, error) {
	log.L.Debugf("SandboxStatus, id: %s", req.SandboxID)

	sb, err := s.getSandbox(req.SandboxID)
	if err != nil {
		return nil, err
	}
	p := sb.task()

	// CRI maps State to a PodSandboxState by name. A created sandbox is not
	// ready: the sentry has not booted yet.
	state := "SANDBOX_NOTREADY"
	switch st, err := p.Status(ctx); {
	case err != nil:
		log.L.Debugf("Status of sandbox %q: %v", sb.id, err)
	case st == "running":
		state = "SANDBOX_READY"
	}

	resp := &api.SandboxStatusResponse{
		SandboxID: sb.id,
		Pid:       uint32(p.Pid()),
		State:     state,
		CreatedAt: protobuf.ToTimestamp(sb.createdAt),
		ExitedAt:  protobuf.ToTimestamp(p.ExitedAt()),
	}
	if req.Verbose {
		info := sandboxInfo{
			Pid:       uint32(p.Pid()),
			SandboxID: sb.id,
		}
		if spec, err := utils.ReadSpec(sb.bundle); err == nil {
			info.RuntimeSpec = spec
		}
		if b, err := json.Marshal(&info); err != nil {
			log.L.Warningf("Marshaling info for sandbox %q: %v", sb.id, err)
		} else {
			resp.Info = map[string]string{"info": string(b)}
		}
	}
	return resp, nil
}

// sandboxInfo is SandboxStatusResponse.Info, in the shape containerd's
// podsandbox controller reports.
type sandboxInfo struct {
	Pid         uint32      `json:"pid"`
	SandboxID   string      `json:"sandboxID"`
	RuntimeSpec *specs.Spec `json:"runtimeSpec,omitempty"`
}

// PingSandbox implements api.TTRPCSandboxService.PingSandbox.
func (s *runscService) PingSandbox(ctx context.Context, req *api.PingRequest) (*api.PingResponse, error) {
	return &api.PingResponse{}, nil
}

// ShutdownSandbox implements api.TTRPCSandboxService.ShutdownSandbox.
func (s *runscService) ShutdownSandbox(ctx context.Context, req *api.ShutdownSandboxRequest) (*api.ShutdownSandboxResponse, error) {
	log.L.Debugf("ShutdownSandbox, id: %s", req.SandboxID)

	s.mu.Lock()
	// An unknown id is fine: containerd also calls this after a failed
	// CreateSandbox.
	sb := s.sandbox
	if sb != nil && sb.id == req.SandboxID {
		s.sandbox = nil
	} else {
		sb = nil
	}
	remaining := len(s.containers)
	s.mu.Unlock()

	// containerd does not run `shim delete` after this, so remove the runsc
	// sandbox here in case StopSandbox never ran, e.g. after a failed
	// StartSandbox or once the sentry died on its own.
	if sb != nil {
		if err := sb.task().Runtime().Delete(ctx, sb.id, &runsccmd.DeleteOpts{Force: true}); err != nil {
			log.L.Warningf("Destroying sandbox %q: %v", sb.id, err)
		}
	}
	if remaining > 0 {
		log.L.Warningf("Shutting down sandbox %q with %d containers still registered", req.SandboxID, remaining)
	}
	if s.platform != nil {
		s.platform.Close()
	}

	// containerd deletes the bundle once this returns, so the shim must exit.
	s.shutdown.Shutdown()
	return &api.ShutdownSandboxResponse{}, nil
}

// SandboxMetrics implements api.TTRPCSandboxService.SandboxMetrics.
func (s *runscService) SandboxMetrics(ctx context.Context, req *api.SandboxMetricsRequest) (*api.SandboxMetricsResponse, error) {
	log.L.Debugf("SandboxMetrics, id: %s", req.SandboxID)

	sb, err := s.getSandbox(req.SandboxID)
	if err != nil {
		return nil, err
	}
	stats, err := sb.container.Stats(ctx)
	if err != nil {
		return nil, errgrpc.ToGRPC(err)
	}
	return &api.SandboxMetricsResponse{
		Metrics: &apitypes.Metric{
			Timestamp: protobuf.ToTimestamp(time.Now()),
			ID:        sb.id,
			Data:      stats.Stats,
		},
	}, nil
}

// forceDeleteFromBundle runs `runsc delete --force` for id, using the runsc
// root and binary NewContainer saved in the bundle. It is a no-op if
// NewContainer failed before saving them.
func forceDeleteFromBundle(ctx context.Context, bundle, id string) {
	var st State
	if err := st.Load(bundle); err != nil {
		return
	}
	ns, err := namespaces.NamespaceRequired(ctx)
	if err != nil {
		log.L.Warningf("Destroying sandbox %q: %v", id, err)
		return
	}
	r := proc.NewRunsc(st.Options.Root, bundle, ns, st.Options.BinaryName, nil, nil)
	if err := r.Delete(ctx, id, &runsccmd.DeleteOpts{Force: true}); err != nil {
		log.L.Warningf("Destroying sandbox %q: %v", id, err)
	}
}

// runtimeOptions returns the runtime options manager.Start saved in the
// bundle, or nil if there are none or they cannot be parsed, in which case the
// sandbox uses the config file.
func runtimeOptions(bundle string) *anypb.Any {
	data, err := utils.ReadRuntimeOptions(bundle)
	if err != nil {
		log.L.Warningf("Reading saved runtime options, using the config file instead: %v", err)
		return nil
	}
	if data == nil {
		return nil
	}
	opts := &anypb.Any{}
	if err := proto.Unmarshal(data, opts); err != nil {
		log.L.Warningf("Unmarshaling saved runtime options, using the config file instead: %v", err)
		return nil
	}
	return opts
}

// sandboxSpec builds the OCI spec for a sandbox from its CRI pod config.
//
// It has no Process and no Root, as `runsc create --no-root-container`
// requires. The rest mirrors what containerd puts on the pause container's
// spec.
func sandboxSpec(id, netnsPath string, annotations map[string]string, config *podSandboxConfig) *specs.Spec {
	spec := &specs.Spec{
		Version:  specs.Version,
		Hostname: config.hostname,
		Linux:    &specs.Linux{},
		// annotations has been filtered by the runtime handler's
		// pod_annotations allowlist. config.Annotations has not, so copying it
		// would let any pod reconfigure runsc through dev.gvisor.*.
		Annotations: make(map[string]string, len(annotations)+8),
	}
	for k, v := range annotations {
		spec.Annotations[k] = v
	}
	warnDroppedAnnotations(annotations, config.annotations)

	spec.Annotations[specutils.ContainerdContainerTypeAnnotation] = specutils.ContainerdContainerTypeSandbox
	spec.Annotations[specutils.ContainerdSandboxIDAnnotation] = id
	spec.Annotations[sandboxNameAnnotation] = config.name
	spec.Annotations[sandboxNamespaceAnnotation] = config.namespace
	spec.Annotations[sandboxUIDAnnotation] = config.uid
	spec.Annotations[sandboxLogDirAnnotation] = config.logDirectory

	if config.cgroupParent != "" {
		spec.Linux.CgroupsPath = cgroupsPath(config.cgroupParent, id)
	}
	if len(config.sysctls) > 0 {
		spec.Linux.Sysctl = config.sysctls
	}
	if res := config.resources; res != nil {
		spec.Annotations[sandboxCPUPeriodAnnotation] = strconv.FormatInt(res.cpuPeriod, 10)
		spec.Annotations[sandboxCPUQuotaAnnotation] = strconv.FormatInt(res.cpuQuota, 10)
		spec.Annotations[sandboxCPUSharesAnnotation] = strconv.FormatInt(res.cpuShares, 10)
		spec.Annotations[sandboxMemAnnotation] = strconv.FormatInt(res.memoryLimit, 10)
	}

	if !config.hostNetwork {
		spec.Linux.Namespaces = append(spec.Linux.Namespaces, specs.LinuxNamespace{
			Type: specs.NetworkNamespace,
			Path: netnsPath,
		})
	}
	return spec
}

// warnDroppedAnnotations logs pod dev.gvisor.* annotations that did not reach
// the sandbox. Under CRI, containerd leaves CreateSandboxRequest.Annotations
// empty (sandbox_run.go passes only WithOptions and WithNetNSPath), so
// pod_annotations has no effect on this path.
func warnDroppedAnnotations(passed, podAnnotations map[string]string) {
	for k := range podAnnotations {
		if !strings.HasPrefix(k, gvisorAnnotationPrefix) {
			continue
		}
		if _, ok := passed[k]; ok {
			continue
		}
		log.L.Warnf("Ignoring pod annotation %q: containerd does not pass pod annotations to the sandbox API. Configure the runtime handler's config.toml instead.", k)
	}
}

// cgroupsPath returns the sandbox cgroup path the way containerd's CRI plugin
// does for the pause container.
func cgroupsPath(cgroupsParent, id string) string {
	base := path.Base(cgroupsParent)
	if strings.HasSuffix(base, ".slice") {
		// systemd format: "slice:prefix:name".
		return strings.Join([]string{base, "cri-containerd", id}, ":")
	}
	return filepath.Join(cgroupsParent, id)
}
