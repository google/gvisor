// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package root

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/docker/docker/api/types/mount"
	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/runsc/flag"
)

var (
	containerdVersion = flag.String("containerd_version", "2.2.3",
		"containerd version to test against; must be baked into the harness image")
	harnessImage = flag.String("harness_image", "containerd/harness",
		"harness image, relative to images/")
	harnessTestImages = flag.String("harness_test_images",
		"basic/alpine,basic/python,basic/busybox,basic/symlink-resolv,basic/httpd,basic/ubuntu",
		"images to stage into the harness; must match the load-* deps of containerd-test-% in the Makefile")
	noHarness = flag.Bool("no_harness", false,
		"run directly against a host containerd instead of the harness (legacy path)")
)

const (
	harnessEnv = "GVISOR_CONTAINERD_HARNESS"
	runtimeDir = "/runtime"
	imageDir   = "/cri-images"
)

func inHarness() bool {
	return os.Getenv(harnessEnv) != ""
}

func useHarness() bool {
	return !*noHarness && !inHarness()
}

// runInHarness runs the test in a containerd harness.
// Returns the exit code of the harness.
func runInHarness(ctx context.Context) int {
	logger := testutil.DefaultLogger("harness")

	code, err := launch(ctx, logger)
	if err != nil {
		fmt.Fprintf(os.Stderr, "harness: %v\n", err)
		if code == 0 {
			code = 1
		}
	}
	return code
}

// launch launches the containerd harness.
// Returns the exit code of the harness and an error if the harness failed to launch.
func launch(ctx context.Context, logger testutil.Logger) (int, error) {
	self, err := os.Executable()
	if err != nil {
		return 1, fmt.Errorf("cannot locate test binary: %w", err)
	}
	if self, err = filepath.EvalSymlinks(self); err != nil {
		return 1, fmt.Errorf("cannot resolve test binary: %w", err)
	}

	// Stage the runtime and test binary into the containerd harness.
	runtimeHostDir, err := stageRuntime(self)
	if err != nil {
		return 1, err
	}
	defer os.RemoveAll(runtimeHostDir)

	var mounts []mount.Mount
	mounts = append(mounts, mount.Mount{
		Type:     mount.TypeBind,
		Source:   runtimeHostDir,
		Target:   runtimeDir,
		ReadOnly: true,
	})

	// Stage the containerd daemon config.
	daemonJSON, err := writeDaemonConfig()
	if err != nil {
		return 1, err
	}
	defer os.RemoveAll(filepath.Dir(daemonJSON))
	mounts = append(mounts, mount.Mount{
		Type:     mount.TypeBind,
		Source:   daemonJSON,
		Target:   "/etc/docker/daemon.json",
		ReadOnly: true,
	})

	// Stage the test images.
	staged, err := stageImages(logger)
	if err != nil {
		return 1, err
	}
	mounts = append(mounts,
		mount.Mount{
			Type:     mount.TypeBind,
			Source:   staged,
			Target:   imageDir,
			ReadOnly: true,
		},
		mount.Mount{
			Type:   mount.TypeBind,
			Source: "/sys/fs/cgroup",
			Target: "/sys/fs/cgroup",
		},
		mount.Mount{Type: mount.TypeTmpfs, Target: "/tmp"},
		mount.Mount{Type: mount.TypeVolume, Target: "/var/lib"},
	)

	runtime := os.Getenv("RUNTIME")
	if runtime == "" {
		runtime = "runsc"
	}

	d := dockerutil.MakeNativeContainer(ctx, logger)
	defer d.CleanUp(ctx)

	opts := dockerutil.RunOpts{
		Image:        *harnessImage,
		Privileged:   true,
		Init:         true,
		CgroupnsMode: "host",
		SecurityOpts: []string{
			"seccomp=unconfined",
			"apparmor=unconfined",
			"label=type:container_engine_t",
		},
		Mounts: mounts,
		Env: []string{
			harnessEnv + "=1",
			"CONTAINERD_VERSION=" + *containerdVersion,
			"RUNTIME=" + runtime,
			"GVISOR_CRI_IMAGE_DIR=" + imageDir,
			"GVISOR_SIDECAR_BINARIES_DIR=" + runtimeDir + "/gvisor-bin",
			"TEST_TMPDIR=",
		},
	}

	// Launch the harness with the this test binary and args.
	binName := filepath.Base(self)
	args := append([]string{filepath.Join(runtimeDir, binName)}, os.Args[1:]...)
	logger.Logf("launching harness: containerd %s, runtime %s", *containerdVersion, runtime)

	if err := d.Create(ctx, opts, args...); err != nil {
		return 1, fmt.Errorf("creating harness container: %w", err)
	}
	if err := d.Start(ctx); err != nil {
		return 1, fmt.Errorf("starting harness container: %w", err)
	}

	streamDone := make(chan struct{})
	go func() {
		defer close(streamDone)
		_ = d.StreamOutput(ctx, os.Stdout, os.Stderr)
	}()

	waitErr := d.Wait(ctx)
	<-streamDone
	if waitErr != nil {
		return 1, fmt.Errorf("harness container failed: %w", waitErr)
	}
	return 0, nil
}

func stageRuntime(self string) (string, error) {
	// Create a temporary directory for the runtime and test binary.
	dir, err := os.MkdirTemp("", "harness-runtime")
	if err != nil {
		return "", err
	}
	if err := os.Chmod(dir, 0755); err != nil {
		os.RemoveAll(dir)
		return "", err
	}

	// Copy the release tree into the temporary directory.
	root, err := testutil.FindFile("release")
	if err != nil {
		os.RemoveAll(dir)
		return "", fmt.Errorf("cannot locate release tree: %w", err)
	}

	count := 0
	// Walk the release tree and copy it to the temporary directory so we can mount it into the
	// harness.
	err = filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dir, rel)
		if fi.IsDir() {
			return os.MkdirAll(target, 0755)
		}
		real, err := filepath.EvalSymlinks(p)
		if err != nil {
			return fmt.Errorf("cannot resolve %q: %w", p, err)
		}
		count++
		return copyFile(real, target, 0755)
	})
	if err != nil {
		os.RemoveAll(dir)
		return "", fmt.Errorf("copying release files: %w", err)
	}
	if count == 0 {
		os.RemoveAll(dir)
		return "", fmt.Errorf("release tree %q is empty", root)
	}

	// Copy the test binary into the temporary directory.
	selfReal, err := filepath.EvalSymlinks(self)
	if err != nil {
		os.RemoveAll(dir)
		return "", fmt.Errorf("cannot resolve test binary: %w", err)
	}
	binName := filepath.Base(self)
	if err := copyFile(selfReal, filepath.Join(dir, binName), 0755); err != nil {
		os.RemoveAll(dir)
		return "", fmt.Errorf("copying test binary: %w", err)
	}

	return dir, nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}

// writeDaemonConfig writes a containerd daemon config to a temporary directory.
// Returns the path to the config file.
func writeDaemonConfig() (string, error) {
	dir, err := os.MkdirTemp("", "harness-docker")
	if err != nil {
		return "", err
	}
	runtime := os.Getenv("RUNTIME")
	if runtime == "" {
		runtime = "runsc"
	}
	body := fmt.Sprintf(`{"runtimes": {%q: {"path": %q}}}`,
		runtime, filepath.Join(runtimeDir, "runsc"))
	p := filepath.Join(dir, "daemon.json")
	if err := os.WriteFile(p, []byte(body), 0644); err != nil {
		return "", err
	}
	return p, nil
}

// stageImages stages the images listed in harnessTestImages into the harness.
// Saves each image to a tar file in the cache directory so it can be mounted into the containerd
// harness. // Returns the directory containing the staged images.
func stageImages(logger testutil.Logger) (string, error) {
	cacheDir := filepath.Join(os.TempDir(), "gvisor-cri-images")
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return "", err
	}
	// Stage each image into the harness's cache directory.
	for _, image := range strings.Split(*harnessTestImages, ",") {
		image = strings.TrimSpace(image)
		if image == "" {
			continue
		}
		p := filepath.Join(cacheDir, tarNameForImage(image))
		if fi, err := os.Stat(p); err == nil && fi.Size() > 0 {
			continue
		}
		tmpFile := p + ".tmp"
		f, err := os.OpenFile(tmpFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			return "", err
		}
		if err := dockerutil.Save(logger, image, f); err != nil {
			f.Close()
			os.Remove(tmpFile)
			return "", fmt.Errorf("staging %q (is it loaded? try `make load-%s`): %w",
				image, strings.ReplaceAll(image, "/", "_"), err)
		}
		if err := f.Close(); err != nil {
			os.Remove(tmpFile)
			return "", err
		}
		if err := os.Rename(tmpFile, p); err != nil {
			return "", err
		}
	}
	return cacheDir, nil
}

// tarNameForImage returns the name of the tar file for the given image.
func tarNameForImage(image string) string {
	return strings.ReplaceAll(image, "/", "_") + ".tar"
}
