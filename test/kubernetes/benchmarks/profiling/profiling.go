// Copyright 2024 The gVisor Authors.
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

// Package profiling helps with getting profiles from running benchmarks.
package profiling

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/flate"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/pprof/profile"
	"golang.org/x/time/rate"
	"google.golang.org/protobuf/proto"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/runsc/flag"
	k8s "gvisor.dev/gvisor/test/kubernetes"
	"gvisor.dev/gvisor/test/kubernetes/k8sctx"
	"gvisor.dev/gvisor/test/kubernetes/testcluster"
	"gvisor.dev/gvisor/test/metricsviz"
	appsv1 "k8s.io/api/apps/v1"
	v13 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	profileDir                    = flag.String("gvisor-profile-dir", "", "if non-empty, record profiles and save them under this directory")
	profileCPU                    = flag.Bool("gvisor-profile-cpu", false, "if --gvisor-profile-dir is non-empty, take a CPU profile")
	profileBlock                  = flag.Bool("gvisor-profile-block", false, "if --gvisor-profile-dir is non-empty, take a block profile")
	profileMutex                  = flag.Bool("gvisor-profile-mutex", false, "if --gvisor-profile-dir is non-empty, take a mutex profile")
	profileMetrics                = flag.String("gvisor-profiling-metrics", "", "comma separated list of metric names to sample during the benchmark")
	profileMetricsRateMicrosecond = flag.Int("gvisor-profiling-metrics-rate-us", 1000, "target rate (in microseconds) at which profiling metrics will be snapshotted")
	profileDebug                  = flag.Bool("gvisor-profile-debug", false, "if --gvisor-profile-dir is non-empty, also capture runsc debug logs")
)

const (
	setupPodName            = "runsc-profiling-setup"
	k8sApp                  = "k8s-app"
	hostMountDir            = "/host"
	profileHelperImageAMD64 = k8s.ImageRepoPrefix + "benchmarks/profile-helper_x86_64:latest"
	profileHelperImageARM64 = k8s.ImageRepoPrefix + "benchmarks/profile-helper_aarch64:latest"
)

// postProcessor is a function that is called after a profiling run completes.
type postProcessor func(ctx context.Context, t *testing.T, run *profileRun, profileType, profilePath string) error

// postProcessors is a list of post processors to run after a profiling run completes.
var postProcessors []postProcessor

func profileDSTemplate(cluster *testcluster.TestCluster) appsv1.DaemonSet {
	return appsv1.DaemonSet{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "apps/v1",
			Kind:       "DaemonSet",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: setupPodName,
			Labels: map[string]string{
				k8sApp: setupPodName,
			},
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					k8sApp: setupPodName,
				},
			},
			UpdateStrategy: appsv1.DaemonSetUpdateStrategy{
				Type: appsv1.RollingUpdateDaemonSetStrategyType,
			},
			Template: v13.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"name": setupPodName,
						k8sApp: setupPodName,
					},
				},
				Spec: v13.PodSpec{
					Tolerations: []v13.Toleration{
						cluster.GetGVisorRuntimeToleration(),
						{
							Operator: v13.TolerationOpExists,
						},
					},
					HostNetwork: true,
					HostPID:     true,
					Volumes: []v13.Volume{
						{
							Name: "host",
							VolumeSource: v13.VolumeSource{
								HostPath: &v13.HostPathVolumeSource{
									Path: "/",
								},
							},
						},
					},
					InitContainers: nil, // Will be filled in.
					Containers: []v13.Container{
						{
							Name:  "pause",
							Image: "gcr.io/google-containers/pause",
						},
					},
				},
			},
		},
	}
}

// operation returns details of an init container for profiling.
type operation struct {
	// Name of the operation container.
	// If unset, one will be generated.
	name string

	// Command to pass to the profilehelper binary.
	command []string
}

const (
	runscConfigPath    = hostMountDir + "/run/containerd/runsc/config.toml"
	runscConfigSection = "runsc_config"
)

func removeFlag(flagName string) operation {
	return operation{
		command: []string{
			"profilehelper",
			"--operation=remove-containerd-flag",
			fmt.Sprintf("--containerd-config=%s", runscConfigPath),
			fmt.Sprintf("--containerd-section=%s", runscConfigSection),
			fmt.Sprintf("--flag=%s", flagName),
		},
	}
}

func setFlag(flagName, flagValue string) operation {
	return operation{
		command: []string{
			"profilehelper",
			"--operation=set-containerd-flag",
			fmt.Sprintf("--containerd-config=%s", runscConfigPath),
			fmt.Sprintf("--containerd-section=%s", runscConfigSection),
			fmt.Sprintf("--flag=%s", flagName),
			fmt.Sprintf("--value=%s", flagValue),
		},
	}
}

func makeDir(dirPath string) operation {
	return operation{
		command: []string{"mkdir", "-p", dirPath},
	}
}

func chmodDir(dirPath string, mode int) operation {
	return operation{
		command: []string{"chmod", fmt.Sprintf("%o", mode), dirPath},
	}
}

func deleteDir(dirPath string) operation {
	return operation{
		command: []string{"rm", "-rf", "--one-file-system", dirPath},
	}
}

func streamDir(dirPath string) operation {
	return operation{
		command: []string{
			"profilehelper",
			"--operation=stream-dir",
			fmt.Sprintf("--dir=%s", dirPath),
		},
	}
}

// startsOperations starts the given operations in a DaemonSet.
func startOperations(ctx context.Context, k8sCtx k8sctx.KubernetesContext, c *testcluster.TestCluster, ns *testcluster.Namespace, operations []operation) (*appsv1.DaemonSet, error) {
	ds := profileDSTemplate(c)
	ds.Namespace = ns.Namespace
	ds.ObjectMeta.Namespace = ns.Namespace
	ds.Spec.Template.Namespace = ns.Namespace
	ds.Spec.Template.ObjectMeta.Namespace = ns.Namespace
	c.ConfigureDaemonSetForRuntimeTestNodepool(ctx, &ds)
	ds.Spec.Template.Spec.RuntimeClassName = nil // Must run unsandboxed.
	var image string
	testCPUArch, err := c.RuntimeTestNodepoolArchitecture(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to determine test CPU architecture: %w", err)
	}
	switch testCPUArch {
	case testcluster.CPUArchitectureX86:
		image = profileHelperImageAMD64
	case testcluster.CPUArchitectureARM:
		image = profileHelperImageARM64
	default:
		return nil, fmt.Errorf("unsupported CPU architecture: %q", testCPUArch)
	}
	if image, err = k8sCtx.ResolveImage(ctx, image); err != nil {
		return nil, fmt.Errorf("failed to resolve image %q: %w", image, err)
	}
	for i, op := range operations {
		name := op.name
		if name == "" {
			name = fmt.Sprintf("op-%d", i)
		}
		ds.Spec.Template.Spec.InitContainers = append(ds.Spec.Template.Spec.InitContainers, v13.Container{
			Image:           image,
			Name:            name,
			Command:         op.command,
			SecurityContext: &v13.SecurityContext{Privileged: proto.Bool(true)},
			VolumeMounts: []v13.VolumeMount{
				{
					Name:      "host",
					MountPath: hostMountDir,
				},
			},
		})
	}

	// Delete any pre-existing DaemonSet under the same name.
	// Ignore errors, we'll check errors when creating the new one.
	_ = c.DeleteDaemonset(ctx, &ds)
	newDS, err := c.CreateDaemonset(ctx, &ds)
	if err != nil {
		return nil, fmt.Errorf("failed to create daemonset: %w", err)
	}
	return newDS, nil
}

// profileRun encapsulates data about a profiling run.
// It is used after the run completes so that profiles can be retrieved.
type profileRun struct {
	k8sCtx                k8sctx.KubernetesContext
	c                     *testcluster.TestCluster
	ns                    *testcluster.Namespace
	localProfileDir       string
	inContainerProfileDir string
}

// MaybeSetup sets up profiling if requested. It returns a cleanup function.
// If the returned error is nil, the cleanup function is non-nil and should be
// called regardless of whether profiling is actually enabled or not.
func MaybeSetup(ctx context.Context, t *testing.T, k8sCtx k8sctx.KubernetesContext, c *testcluster.TestCluster, ns *testcluster.Namespace) (func(), error) {
	profileDirName := fmt.Sprintf("%s.%s", t.Name(), time.Now().Format("20060102-150405"))
	profileDirName = regexp.MustCompile("[^-_=.\\w]+").ReplaceAllString(profileDirName, ".")
	hasGVisorRuntime, err := c.HasGVisorTestRuntime(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to check if the cluster uses gVisor: %w", err)
	}

	var setupCommands []operation
	cleanup := func() {}
	if *profileDir != "" || *profileMetrics != "" {
		if !hasGVisorRuntime {
			return nil, fmt.Errorf("profiling was requested yet the cluster does not use gVisor; profiling is only supported with the gVisor runtime")
		}
		profileDir := *profileDir
		if profileDir == "" {
			profileDir = filepath.Join("/tmp/runsc-profiling", t.Name())
		}
		localProfileDir := filepath.Join(profileDir, profileDirName)
		onNodeProfileDir := filepath.Join("/tmp/runsc-profiling", profileDirName)
		inContainerProfileDir := fmt.Sprintf("%s%s", hostMountDir, onNodeProfileDir)
		setupCommands = append(setupCommands,
			makeDir(inContainerProfileDir),
			chmodDir(inContainerProfileDir, 0777),
			setFlag("profile", "true"))
		atLeastOneProfile := *profileMetrics != "" || *profileDebug
		for _, prof := range []struct {
			enabled  *bool
			filename string
			flag     string
		}{
			{profileCPU, "profile_%ID%.cpu.pprof", "profile-cpu"},
			{profileBlock, "profile_%ID%.block.pprof", "profile-block"},
			{profileMutex, "profile_%ID%.mutex.pprof", "profile-mutex"},
		} {
			if *prof.enabled {
				atLeastOneProfile = true
				setupCommands = append(setupCommands, setFlag(prof.flag, filepath.Join(onNodeProfileDir, prof.filename)))
			} else {
				setupCommands = append(setupCommands, removeFlag(prof.flag))
			}
		}
		if !atLeastOneProfile {
			t.Fatal("Must enable --gvisor-profiling-metrics or --gvisor-profile-debug or at least one --gvisor-profile-* type")
		}
		if *profileDebug {
			setupCommands = append(setupCommands,
				setFlag("debug", "true"),
				setFlag("debug-log", filepath.Join(onNodeProfileDir, "logs")+"/"),
			)
		}
		if *profileMetrics != "" {
			setupCommands = append(setupCommands,
				setFlag("profiling-metrics", *profileMetrics),
				setFlag("profiling-metrics-log", filepath.Join(onNodeProfileDir, "profile_%ID%.metrics.log")),
				setFlag("profiling-metrics-rate-us", fmt.Sprintf("%d", *profileMetricsRateMicrosecond)),
			)
		}
		cleanup = func() {
			err := processProfileRun(ctx, t, &profileRun{
				k8sCtx:                k8sCtx,
				c:                     c,
				ns:                    ns,
				localProfileDir:       localProfileDir,
				inContainerProfileDir: inContainerProfileDir,
			})
			if err != nil {
				t.Errorf("Failed to process profiling data: %v", err)
			}
		}
		t.Logf("Profiling is enabled and data will be stored in: %v", localProfileDir)
	} else if hasGVisorRuntime {
		setupCommands = append(setupCommands,
			setFlag("profile", "false"),
			removeFlag("profile-cpu"),
			removeFlag("profile-mutex"),
			removeFlag("profile-block"),
			removeFlag("profiling-metrics"),
			removeFlag("profiling-metrics-log"),
			removeFlag("profiling-metrics-rate-us"),
		)
	}
	if len(setupCommands) > 0 {
		setupCtx, setupCancel := context.WithTimeout(ctx, 2*time.Minute)
		defer setupCancel()
		ds, err := startOperations(setupCtx, k8sCtx, c, ns, setupCommands)
		if err != nil {
			return nil, fmt.Errorf("failed to start profiling setup operations: %w", err)
		}
		if err := c.WaitForDaemonset(setupCtx, ds); err != nil {
			return nil, fmt.Errorf("failed to wait for daemonset: %w", err)
		}
	}
	return cleanup, nil
}

// processProfileRun is called after a profiling run completes.
// It retrieves the profile data from the node and onto the local machine.
func processProfileRun(ctx context.Context, t *testing.T, run *profileRun) error {
	dirOp := streamDir(run.inContainerProfileDir)
	dirOp.name = "profile-stream-dir"
	beforeSpawn := metav1.NewTime(time.Now())
	retrievalCtx, retrievalCancel := context.WithCancel(ctx)
	defer retrievalCancel()
	ds, err := startOperations(retrievalCtx, run.k8sCtx, run.c, run.ns, []operation{
		dirOp,
		setFlag("profile", "false"),
		removeFlag("profile-cpu"),
		removeFlag("profile-mutex"),
		removeFlag("profile-block"),
		removeFlag("profiling-metrics"),
		removeFlag("profiling-metrics-log"),
		removeFlag("profiling-metrics-rate-us"),
		deleteDir(run.inContainerProfileDir),
	})
	if err != nil {
		return err
	}
	logOpts := v13.PodLogOptions{
		Container:  dirOp.name,
		Follow:     true,
		SinceTime:  &beforeSpawn,
		Timestamps: false,
	}
	atLeastOneNode := false
	err = run.c.StreamDaemonSetLogs(retrievalCtx, ds, logOpts, func(logsCtx context.Context, pod v13.Pod, reader io.ReadCloser) error {
		atLeastOneNode = true
		if err := processProfileLogs(logsCtx, t, run, pod, reader); err != nil {
			return err
		}
		t.Logf("Profiling data from node %s was successfully retrieved to: %v", pod.Spec.NodeName, filepath.Join(run.localProfileDir, pod.Spec.NodeName))
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to stream logs: %w", err)
	}
	if !atLeastOneNode {
		return fmt.Errorf("profiling DaemonSet did not run on any node: %v", ds)
	}
	t.Logf("Profiling data was successfully retrieved in: %v", run.localProfileDir)

	// Merge profiles of the same type together.
	for _, profileType := range []string{"cpu", "block", "mutex"} {
		if err := mergeProfiles(ctx, t, run, profileType); err != nil {
			return fmt.Errorf("cannot merge profiles of type %q: %w", profileType, err)
		}
	}

	// Make charts out of profiling metrics.
	if err := processProfilingMetrics(ctx, t, run); err != nil {
		return fmt.Errorf("failed to process profiling metrics: %w", err)
	}

	// Clean up per-node directories if they are now empty.
	if err := removeEmptyDirectories(run.localProfileDir); err != nil {
		return fmt.Errorf("failed to clean up empty directories: %w", err)
	}
	return nil
}

// dirStreamReader reads logs emitted by
// `profilehelper --operation=stream-dir`.
// It sits as the top-level reader in the chain;
// next should be the base64 decoder.
type dirStreamReader struct {
	logsReader io.ReadCloser
	buf        bytes.Buffer
	checksum   hash.Hash
	dataCh     chan []byte
	errCh      chan error
	progressFn func(readBytes, estimatedTotalBytes int64)
}

// processLogs reads container logs and writes base64 data to `r.dataCh`.
// If something goes wrong, it writes to `r.errCh`.
// This should run as a background goroutine for `r.Read` to return anything.
func (r *dirStreamReader) processLogs() {
	const (
		beginPrefix = "BEGIN:"
		dataPrefix  = "DATA:"
		shaPrefix   = "SHA256:"
	)

	scanner := bufio.NewScanner(r.logsReader)
	streamHasBegun := false
	steamHasEnded := false
	var readBytes, estimatedTotalBytes int64
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		err := func() error {
			switch {
			case strings.HasPrefix(line, beginPrefix):
				if streamHasBegun {
					return errors.New("found duplicate stream beginning line")
				}
				if steamHasEnded {
					return errors.New("stream ended but got new beginning line")
				}
				streamHasBegun = true
				beginLineSplit := strings.SplitN(line, ":", 3)
				if len(beginLineSplit) != 3 {
					return fmt.Errorf("invalid stream beginning line: %q", line)
				}
				var err error
				estimatedTotalBytes, err = strconv.ParseInt(beginLineSplit[1], 10, 64)
				if err != nil {
					return fmt.Errorf("invalid stream beginning line: %q: %w", line, err)
				}
			case strings.HasPrefix(line, dataPrefix):
				if !streamHasBegun {
					return errors.New("stream began without header")
				}
				if steamHasEnded {
					return errors.New("stream ended but got new data line")
				}
				data := []byte(line[len(dataPrefix):])
				if len(data) > 0 {
					r.checksum.Write(data)
					r.dataCh <- data
					readBytes += int64(len(data))
					if r.progressFn != nil && estimatedTotalBytes > 0 {
						r.progressFn(readBytes, estimatedTotalBytes)
					}
				}
			case strings.HasPrefix(line, shaPrefix):
				if !streamHasBegun {
					return errors.New("stream ended without header")
				}
				if steamHasEnded {
					return errors.New("stream began but got new hash line")
				}
				hexSum := line[len(shaPrefix):]
				gotSum := fmt.Sprintf("%x", r.checksum.Sum(nil))
				if hexSum != gotSum {
					return fmt.Errorf("checksum mismatch: stream hash was %s but stream footer said the hash should have been %s", gotSum, hexSum)
				}
				steamHasEnded = true
			case line == "":
				// Do nothing.
			default:
				return fmt.Errorf("invalid line format: %q", line)
			}
			return nil
		}()
		if err != nil {
			r.errCh <- err
			break
		}
	}
	r.errCh <- io.EOF
}

// Read implements `io.Reader.Read`.
func (r *dirStreamReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if r.buf.Len() != 0 {
		return r.buf.Read(p)
	}
	select {
	case data := <-r.dataCh:
		r.buf.Write(data)
		return r.buf.Read(p)
	case err := <-r.errCh:
		return 0, err
	}
}

// countingWriter is a writer that counts the number of bytes written.
type countingWriter struct {
	w       io.Writer
	counter *atomicbitops.Int64
}

// Write implements `io.Writer.Write`.
func (w *countingWriter) Write(p []byte) (int, error) {
	n, err := w.w.Write(p)
	w.counter.Add(int64(n))
	return n, err
}

// processProfileLogs processes logs from one container containing the
// profiling information.
func processProfileLogs(ctx context.Context, t *testing.T, run *profileRun, pod v13.Pod, reader io.ReadCloser) error {
	defer reader.Close()
	perNodeLocalDir := path.Join(run.localProfileDir, pod.Spec.NodeName)
	var decodedBytes atomicbitops.Int64
	var firstByteTime time.Time
	progressLog := rate.NewLimiter(rate.Every(5*time.Second), 1)
	processor := &dirStreamReader{
		logsReader: reader,
		checksum:   sha256.New(),
		dataCh:     make(chan []byte),
		errCh:      make(chan error),
		progressFn: func(readBytes, estimatedTotalBytes int64) {
			now := time.Now()
			if firstByteTime.IsZero() { // First progress update.
				firstByteTime = now
				// Don't allow any logging for the first few seconds,
				// any ETA it provides will be bunk.
				progressLog.Allow()
				return
			}
			if progressLog.Allow() {
				readBytes = max(readBytes, decodedBytes.Load())
				progress := float64(readBytes) / float64(estimatedTotalBytes)
				remaining := "unknown"
				if progress > 0 && progress <= 1.0 {
					sinceStartMillis := float64(now.Sub(firstByteTime).Milliseconds())
					remainingDuration := time.Duration(sinceStartMillis/progress-sinceStartMillis) * time.Millisecond
					if remainingDuration > 0 {
						remaining = fmt.Sprintf("%s, ETA: %s", remainingDuration.Truncate(time.Second), now.Add(remainingDuration).Format(time.TimeOnly))
					}
				}
				t.Logf("[%s] Downloading profile data: Progress: %.1f%%, remaining: %s", time.Now().Format(time.TimeOnly), 100.0*progress, remaining)
			}
		},
	}
	go processor.processLogs()
	b64Dec := base64.NewDecoder(base64.StdEncoding, processor)
	fr := flate.NewReader(b64Dec)
	tr := tar.NewReader(fr)
	atLeastOneFile := false
	for hdr, tarErr := tr.Next(); tarErr == nil; hdr, tarErr = tr.Next() {
		if !filepath.IsLocal(hdr.Name) {
			return fmt.Errorf("bad filename in tar archive: %q", hdr.Name)
		}
		localPath := filepath.Join(perNodeLocalDir, hdr.Name)
		localDir := filepath.Dir(localPath)
		if err := os.MkdirAll(localDir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %q: %w", localDir, err)
		}
		f, err := os.OpenFile(localPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, fs.FileMode(hdr.Mode))
		if err != nil {
			return fmt.Errorf("failed to create file %q: %w", localPath, err)
		}
		copied, err := io.Copy(&countingWriter{w: f, counter: &decodedBytes}, tr)
		f.Close()
		if err != nil {
			return fmt.Errorf("failed to write to file %q: %w", localPath, err)
		}
		if copied != hdr.Size {
			return fmt.Errorf("written file has wrong size: tar header says %d bytes, but stream only contained %d bytes", hdr.Size, copied)
		}
		t.Logf("Finished downloading file: %v", localPath)
		atLeastOneFile = true
	}
	if !atLeastOneFile {
		return errors.New("found no profiling data in output")
	}
	return nil
}

func mergeProfiles(ctx context.Context, t *testing.T, run *profileRun, profileType string) error {
	wantSubstring := fmt.Sprintf(".%s.pprof", profileType)
	var profilePaths []string
	err := filepath.Walk(run.localProfileDir, func(path string, info fs.FileInfo, walkErr error) error {
		switch {
		case walkErr != nil: // Keep walking other directories, so don't propagate error here.
		case info.IsDir():
		case !strings.Contains(filepath.Base(path), wantSubstring):
		default:
			profilePaths = append(profilePaths, path)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("cannot traverse %q: %w", run.localProfileDir, err)
	}
	if len(profilePaths) == 0 {
		return nil
	}
	profiles := make([]*profile.Profile, len(profilePaths))
	for i, profilePath := range profilePaths {
		profileFile, err := os.Open(profilePath)
		if err != nil {
			return fmt.Errorf("cannot open %q: %w", profilePath, err)
		}
		defer profileFile.Close()
		prof, err := profile.Parse(profileFile)
		if err != nil {
			return fmt.Errorf("cannot parse %q: %w", profilePath, err)
		}
		profiles[i] = prof
	}
	merged, err := profile.Merge(profiles)
	if err != nil {
		return fmt.Errorf("cannot merge %q: %w", profilePaths, err)
	}
	merged = merged.Compact()
	filenamePrefix := ""
	if len(profiles) > 1 {
		filenamePrefix = "merged_"
	}
	mergedPath := filepath.Join(run.localProfileDir, fmt.Sprintf("%s%s.pprof", filenamePrefix, profileType))
	mergedFile, err := os.Create(mergedPath)
	if err != nil {
		return fmt.Errorf("cannot create %q: %w", mergedPath, err)
	}
	if err := merged.Write(mergedFile); err != nil {
		mergedFile.Close()
		os.Remove(mergedPath)
		return fmt.Errorf("cannot write merged %s profile to %q: %w", profileType, mergedPath, err)
	}
	mergedFile.Close()
	for _, profilePath := range profilePaths {
		if err := os.Remove(profilePath); err != nil {
			return fmt.Errorf("cannot remove %q: %w", profilePath, err)
		}
	}
	t.Logf("%s profile was successfully written to: %v", strings.ToUpper(profileType), mergedPath)

	// Do post-processing on the merged profile.
	for _, postProc := range postProcessors {
		if err := postProc(ctx, t, run, profileType, mergedPath); err != nil {
			return fmt.Errorf("failed to post-process profiles: %w", err)
		}
	}
	return nil
}

func processProfilingMetrics(ctx context.Context, t *testing.T, run *profileRun) error {
	var metricsLogs []string
	err := filepath.Walk(run.localProfileDir, func(path string, info fs.FileInfo, walkErr error) error {
		switch {
		case walkErr != nil: // Keep walking other directories, so don't propagate error here.
		case info.IsDir():
		case !strings.HasSuffix(filepath.Base(path), ".metrics.log"):
		default:
			metricsLogs = append(metricsLogs, path)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("cannot traverse %q: %w", run.localProfileDir, err)
	}
	for _, metricsLog := range metricsLogs {
		metricsviz.FromProfilingMetricsLogFile(ctx, t, metricsLog)
	}
	return nil
}

// removeEmptyDirectories recursively removes empty dirs under `fromDir`.
func removeEmptyDirectories(fromDir string) error {
	for keepGoing := true; keepGoing; {
		var toRemove []string
		err := filepath.Walk(fromDir, func(path string, info fs.FileInfo, walkErr error) error {
			if walkErr != nil {
				// Keep walking other directories, so return nil here.
				return nil
			}
			if !info.IsDir() {
				return nil
			}
			dirEntries, err := os.ReadDir(path)
			if err != nil {
				return fmt.Errorf("cannot read directory %q: %w", path, err)
			}
			if len(dirEntries) == 0 {
				toRemove = append(toRemove, path)
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("cannot traverse %q: %w", fromDir, err)
		}
		keepGoing = len(toRemove) > 0
		for _, path := range toRemove {
			if err := os.Remove(path); err != nil {
				return fmt.Errorf("cannot remove %q: %w", path, err)
			}
		}
	}
	return nil
}
