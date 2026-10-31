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

// Package checkpointfile benchmarks decoding and encoding the kernel state of
// a checkpoint.
//
// BenchmarkCheckpointFile starts nginx with a fixed number of worker
// processes, waits until it listens and its CPU usage has stayed flat,
// checkpoints it, and reports the sizes of the checkpoint files.
package checkpointfile

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/client"
	"golang.org/x/sys/unix"

	pkgcontext "gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/cpuid"
	"gvisor.dev/gvisor/pkg/fdnotifier"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/memutil"
	"gvisor.dev/gvisor/pkg/sentry/checkpoint"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/host"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	"gvisor.dev/gvisor/pkg/sentry/platform/systrap"
	"gvisor.dev/gvisor/pkg/sentry/state/checkpointfiles"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/state"
	"gvisor.dev/gvisor/pkg/state/statefile"
	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/runsc/boot"
	"gvisor.dev/gvisor/test/benchmarks/harness"
)

const (
	// workers is the number of nginx worker processes.
	// Fixed so that the checkpoint taken here is consistent.
	workers = 4

	// quiesceInterval is the interval between CPU usage samples, and
	// quiesceSamples is the number of consecutive intervals in which the
	// container must use less than quiesceMaxCPU of a CPU.
	// Used to keep the checkpoint roughly consistent in terms of kernel
	// state.
	quiesceInterval = 500 * time.Millisecond
	quiesceSamples  = 4
	quiesceMaxCPU   = 0.005
	quiesceTimeout  = 60 * time.Second
)

// BenchmarkCheckpointFile reports various benchmark metrics about a
// checkpointed kernel.
func BenchmarkCheckpointFile(b *testing.B) {
	ctx := context.Background()
	var (
		stateFile     []byte
		sizes         map[string]int64
		names, mounts []string
	)
	if *checkpointDir != "" {
		var err error
		stateFile, sizes, names, mounts, err = readCheckpointDir(*checkpointDir)
		if err != nil {
			b.Fatalf("failed to read checkpoint directory: %v", err)
		}
	} else {
		if !testutil.IsCheckpointSupported() {
			b.Skip("Checkpoint is not supported on this runtime.")
		}
		gvisor, err := dockerutil.IsGVisorRuntime(ctx)
		if err != nil {
			b.Fatalf("failed to check runtime: %v", err)
		}
		if !gvisor {
			b.Skip("The checkpoint file benchmark requires runsc.")
		}
		machine, err := harness.GetMachine()
		if err != nil {
			b.Fatalf("failed to get machine: %v", err)
		}
		defer machine.CleanUp()
		stateFile, sizes, names, mounts = checkpointNginx(ctx, b, machine)
	}
	ctx = restoreContext(b, names, mounts)
	// Tasks create their platform contexts when they are loaded.
	sys, err := systrap.New(platform.Options{})
	if err != nil {
		b.Fatalf("failed to create platform: %v", err)
	}
	plat := stubPlatform{sys}

	// DecodeGC decodes the kernel as runsc restore does, with garbage
	// collection enabled. It reports the garbage collections during the
	// decoding, their stop-the-world pause time, the peak heap, and the heap
	// retained once decoding is done (by the kernel, and by any state kept by
	// the state package).
	b.Run("DecodeGC", func(b *testing.B) {
		b.ReportAllocs()
		var (
			cpu                  time.Duration
			gcs, pauseNs         uint64
			liveBytes, peakBytes int64
		)
		b.ResetTimer()
		b.StopTimer()
		for i := 0; i < b.N; i++ {
			func() {
				ctx, cleanup := withHostFDs(b, ctx, names)
				defer cleanup()
				runtime.GC()
				var before, after runtime.MemStats
				runtime.ReadMemStats(&before)
				stop := sampleHeapPeak()
				defer stop()
				cpu0 := processCPU(b)
				b.StartTimer()
				k, err := loadKernel(ctx, plat, stateFile, true)
				b.StopTimer()
				cpu += processCPU(b) - cpu0
				peakBytes += stop()
				if err != nil {
					b.Fatal(err)
				}
				runtime.ReadMemStats(&after)
				gcs += uint64(after.NumGC - before.NumGC)
				pauseNs += after.PauseTotalNs - before.PauseTotalNs
				runtime.GC()
				runtime.ReadMemStats(&after)
				liveBytes += max(int64(after.HeapAlloc)-int64(before.HeapAlloc), 0)
				runtime.KeepAlive(k)
			}()
		}
		n := float64(b.N)
		b.ReportMetric(float64(cpu.Nanoseconds())/n, "cpu-ns")
		b.ReportMetric(float64(gcs)/n, "gcs/op")
		b.ReportMetric(float64(pauseNs)/n, "gc-pause-ns/op")
		b.ReportMetric(float64(peakBytes)/n, "heap-peak-B")
		b.ReportMetric(float64(liveBytes)/n, "heap-live-B")
	})

	for _, mode := range []struct {
		// suffix is appended to the sub-benchmark names.
		suffix string
		// statefile is true if the state file is written and read
		// like the input checkpoint: through statefile.NewWriter with its
		// metadata, and directly from statefile.NewReader.
		// Otherwise, the encoding is written to a counting writer
		// and read through a bufio.Reader.
		statefile bool
	}{
		{suffix: ""},
		{suffix: "Statefile", statefile: true},
	} {
		b.Run("Decode"+mode.suffix, func(b *testing.B) {
			b.ReportAllocs()
			var cpu time.Duration
			b.ResetTimer()
			b.StopTimer()
			for i := 0; i < b.N; i++ {
				func() {
					ctx, cleanup := withHostFDs(b, ctx, names)
					defer cleanup()
					cpu += cpuTime(b, func() error {
						_, err := loadKernel(ctx, plat, stateFile, mode.statefile)
						return err
					})
				}()
			}
			b.ReportMetric(float64(cpu.Nanoseconds())/float64(b.N), "cpu-ns")
			b.ReportMetric(float64(sizes[checkpointfiles.StateFileName]), "state-file-B")
			b.ReportMetric(float64(sizes[checkpointfiles.PagesFileName]), "pages-file-B")
			b.ReportMetric(float64(sizes[checkpointfiles.PagesMetadataFileName]), "pages-metadata-B")
			var total int64
			for _, size := range sizes {
				total += size
			}
			b.ReportMetric(float64(total), "checkpoint-total-B")
		})
		b.Run("Encode"+mode.suffix, func(b *testing.B) {
			b.ReportAllocs()
			var cpu time.Duration
			var encodedBytes int64
			var encoded bytes.Buffer
			var metadata map[string]string
			if mode.statefile {
				var err error
				metadata, err = statefile.MetadataUnsafe(bytes.NewReader(stateFile))
				if err != nil {
					b.Fatalf("reading checkpoint metadata: %v", err)
				}
				// NewWriter supplies its own internal metadata.
				for key := range metadata {
					if strings.HasPrefix(key, "_") {
						delete(metadata, key)
					}
				}
				encoded.Grow(len(stateFile))
			}
			b.ResetTimer()
			b.StopTimer()
			for i := 0; i < b.N; i++ {
				func() {
					ctx, cleanup := withHostFDs(b, ctx, names)
					defer cleanup()
					// This kernel is only partially restored.
					// Acceptable for purposes of benchmarking pkg/state alone.
					k, err := loadKernel(ctx, plat, stateFile, false)
					if err != nil {
						b.Fatal(err)
					}
					if mode.statefile {
						encoded.Reset()
						cpu += cpuTime(b, func() error {
							return saveKernel(ctx, &encoded, k, metadata)
						})
						return
					}
					w := &countingWriter{}
					cpu += cpuTime(b, func() error {
						_, err := state.Save(ctx, w, k)
						return err
					})
					encodedBytes = w.n
				}()
			}
			b.ReportMetric(float64(cpu.Nanoseconds())/float64(b.N), "cpu-ns")
			if mode.statefile {
				// Check the last measured output outside the benchmark timer.
				ctx, cleanup := withHostFDs(b, ctx, names)
				defer cleanup()
				if _, err := loadKernel(ctx, plat, encoded.Bytes(), true); err != nil {
					b.Fatalf("loading encoded state file: %v", err)
				}
				b.ReportMetric(float64(encoded.Len()), "encoded-state-file-B")
			} else {
				b.ReportMetric(float64(encodedBytes), "encoded-kernel-B")
			}
		})
	}
}

// checkpointDir is a directory containing a checkpoint, as an alternative to
// checkpointing nginx with docker.
var checkpointDir = flag.String("checkpoint-dir", "", "directory containing a checkpoint taken by a runsc built from the same tree, and a "+checkpointSpecName+" file listing the names and mounts of its containers; if set, docker is not used")

// checkpointSpecName is the name of the file in checkpointDir describing the
// containers of the checkpoint.
const checkpointSpecName = "spec.json"

// checkpointSpec describes the containers of a checkpoint in checkpointDir.
type checkpointSpec struct {
	// Names are the names that runsc may give the containers.
	Names []string `json:"names"`
	// Mounts are the destinations of the containers' root and mounts.
	Mounts []string `json:"mounts"`
}

// readCheckpointDir reads a checkpoint from dir, which contains the files of
// a checkpoint and a checkpointSpecName file.
func readCheckpointDir(dir string) (stateFile []byte, sizes map[string]int64, names, mounts []string, err error) {
	data, err := os.ReadFile(filepath.Join(dir, checkpointSpecName))
	if err != nil {
		return nil, nil, nil, nil, err
	}
	var spec checkpointSpec
	if err := json.Unmarshal(data, &spec); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("parsing %s: %w", checkpointSpecName, err)
	}
	sizes = make(map[string]int64)
	for name := range checkpointFileNames {
		fi, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, nil, nil, nil, err
		}
		sizes[name] = fi.Size()
	}
	stateFile, err = os.ReadFile(filepath.Join(dir, checkpointfiles.StateFileName))
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return stateFile, sizes, spec.Names, spec.Mounts, nil
}

// TestCheckpointFileRoundTrip decodes the kernel from the checkpoint in
// checkpointDir, and checks that it can be encoded and decoded again, twice.
func TestCheckpointFileRoundTrip(t *testing.T) {
	if *checkpointDir == "" {
		t.Skip("--checkpoint-dir is not set")
	}
	stateFile, _, names, mounts, err := readCheckpointDir(*checkpointDir)
	if err != nil {
		t.Fatalf("failed to read checkpoint directory: %v", err)
	}
	sys, err := systrap.New(platform.Options{})
	if err != nil {
		t.Fatalf("failed to create platform: %v", err)
	}
	plat := stubPlatform{sys}
	data := stateFile
	var sizes []int
	for i := 0; i < 3; i++ {
		ctx, cleanup := withHostFDs(t, restoreContext(t, names, mounts), names)
		// Alternate between reading through a bufio.Reader and directly.
		k, err := loadKernel(ctx, plat, data, i%2 == 1)
		if err != nil {
			t.Fatalf("round %d: %v", i, err)
		}
		var buf bytes.Buffer
		w, err := statefile.NewWriter(&buf, nil, nil)
		if err != nil {
			t.Fatalf("statefile.NewWriter: %v", err)
		}
		fs := k.FeatureSet()
		if _, err := state.Save(ctx, w, &fs); err != nil {
			t.Fatalf("round %d: saving the CPUID feature set: %v", i, err)
		}
		if _, err := state.Save(ctx, w, k); err != nil {
			t.Fatalf("round %d: saving the kernel: %v", i, err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("closing the state file: %v", err)
		}
		cleanup()
		data = buf.Bytes()
		sizes = append(sizes, len(data))
	}
	t.Logf("State file sizes: original %d, re-encoded %v", len(stateFile), sizes)
}

// checkpointNginx checkpoints an idle nginx container, and returns the
// contents of the state file and the sizes of the checkpoint files by name.
func checkpointNginx(ctx context.Context, b *testing.B, machine harness.Machine) (stateFile []byte, sizes map[string]int64, names, mounts []string) {
	b.Helper()
	container := machine.GetContainer(ctx, b)
	defer container.CleanUp(ctx)
	if err := container.Spawn(ctx, dockerutil.RunOpts{
		Image: "benchmarks/nginx",
	}, "nginx", "-c", "/etc/nginx/nginx_gofer.conf", "-g", fmt.Sprintf("worker_processes %d;", workers)); err != nil {
		b.Fatalf("failed to spawn container: %v", err)
	}
	if err := waitListening(ctx, container, 80); err != nil {
		b.Fatalf("nginx is not listening: %v", err)
	}
	if err := waitQuiescent(ctx, container); err != nil {
		b.Fatalf("nginx did not quiesce: %v", err)
	}
	names, mounts, err := containerSpec(container.ID())
	if err != nil {
		b.Fatalf("failed to read the container's spec: %v", err)
	}

	const name = "checkpointfile"
	if err := container.Checkpoint(ctx, name); err != nil {
		b.Fatalf("failed to checkpoint container: %v", err)
	}
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		b.Fatalf("failed to create docker client: %v", err)
	}
	defer cli.Close()
	info, err := cli.Info(ctx)
	if err != nil {
		b.Fatalf("failed to get docker info: %v", err)
	}
	dir := filepath.Join(info.DockerRootDir, "containers", container.ID(), "checkpoints", name)
	entries, err := os.ReadDir(dir)
	if err != nil {
		b.Fatalf("failed to read checkpoint directory (the benchmark must run as root): %v", err)
	}
	sizes = make(map[string]int64)
	for _, e := range entries {
		if !checkpointFileNames[e.Name()] {
			b.Fatalf("unexpected checkpoint file %q in %s", e.Name(), dir)
		}
		fi, err := e.Info()
		if err != nil {
			b.Fatalf("failed to stat checkpoint file: %v", err)
		}
		sizes[e.Name()] = fi.Size()
	}
	if _, ok := sizes[checkpointfiles.StateFileName]; !ok {
		b.Fatalf("no %s in %s", checkpointfiles.StateFileName, dir)
	}
	stateFile, err = os.ReadFile(filepath.Join(dir, checkpointfiles.StateFileName))
	if err != nil {
		b.Fatalf("failed to read state file: %v", err)
	}
	return stateFile, sizes, names, mounts
}

// checkpointFileNames are the names of the files of a full checkpoint.
var checkpointFileNames = map[string]bool{
	checkpointfiles.StateFileName:         true,
	checkpointfiles.PagesFileName:         true,
	checkpointfiles.PagesMetadataFileName: true,
}

// containerSpec returns the names that runsc may give the container, and the
// destinations of its root and mounts, from its spec.
func containerSpec(id string) (names, mounts []string, err error) {
	data, err := os.ReadFile(filepath.Join("/run/containerd/io.containerd.runtime.v2.task/moby", id, "config.json"))
	if err != nil {
		return nil, nil, err
	}
	var spec struct {
		Annotations map[string]string
		Mounts      []struct {
			Destination string
		}
	}
	if err := json.Unmarshal(data, &spec); err != nil {
		return nil, nil, err
	}
	names = []string{"__no_name_0"}
	for k, v := range spec.Annotations {
		if strings.HasSuffix(k, "container-name") || strings.HasSuffix(k, "container_name") {
			names = append(names, v)
		}
	}
	mounts = []string{"/"}
	for _, m := range spec.Mounts {
		mounts = append(mounts, m.Destination)
	}
	return names, mounts, nil
}

// restoreContext returns a context with the memory files that the kernel's
// objects use when they are loaded and saved.
func restoreContext(b testing.TB, names, mounts []string) context.Context {
	b.Helper()
	newMF := func(id checkpoint.ResourceID) *pgalloc.MemoryFile {
		fd, err := memutil.CreateMemFD("checkpointfile", 0)
		if err != nil {
			b.Fatalf("failed to create memory file: %v", err)
		}
		mf, err := pgalloc.NewMemoryFile(os.NewFile(uintptr(fd), "checkpointfile"), pgalloc.MemoryFileOpts{
			DisableMemoryAccounting: true,
			ResourceID:              id,
		})
		if err != nil {
			b.Fatalf("failed to create memory file: %v", err)
		}
		b.Cleanup(mf.Destroy)
		// Allow saving the filesystems that use it again.
		mf.MarkSavable()
		return mf
	}
	mfs := make(map[checkpoint.ResourceID]*pgalloc.MemoryFile)
	for _, name := range names {
		for _, mount := range mounts {
			id := checkpoint.ResourceID{ContainerName: name, Path: mount}
			mfs[id] = newMF(id)
		}
	}
	ctx := context.WithValue(context.Background(), pgalloc.CtxMemoryFile, newMF(checkpoint.ResourceID{}))
	return context.WithValue(ctx, pgalloc.CtxMemoryFileMap, mfs)
}

// withHostFDs returns ctx with host file descriptors for the standard I/O of
// containers with the given names.
func withHostFDs(b testing.TB, ctx context.Context, names []string) (context.Context, func()) {
	b.Helper()
	fdmap := make(map[checkpoint.ResourceID]int)
	var fds []int
	for _, name := range names {
		for stdio := 0; stdio < 3; stdio++ {
			var p [2]int
			if err := unix.Pipe2(p[:], unix.O_CLOEXEC); err != nil {
				b.Fatalf("pipe2: %v", err)
			}
			fds = append(fds, p[0], p[1])
			if stdio == 0 {
				fdmap[host.MakeResourceID(name, stdio)] = p[0]
			} else {
				fdmap[host.MakeResourceID(name, stdio)] = p[1]
			}
		}
	}
	return context.WithValue(ctx, vfs.CtxRestoreFilesystemFDMap, fdmap), func() {
		for _, fd := range fds {
			if fdnotifier.HasFD(int32(fd)) {
				fdnotifier.RemoveFD(int32(fd))
			}
			unix.Close(fd)
		}
	}
}

// waitListening waits for a socket listening on port in the container.
func waitListening(ctx context.Context, container *dockerutil.Container, port int) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := fmt.Sprintf("while ! grep -s -E ':%04X [0-9A-F:]+ 0A' /proc/net/tcp /proc/net/tcp6; do sleep 0.01; done", port)
	if out, err := container.Exec(ctx, dockerutil.ExecOpts{}, "sh", "-c", cmd); err != nil {
		return fmt.Errorf("%w: %s", err, out)
	}
	return nil
}

// waitQuiescent waits until the container's CPU usage stays below
// quiesceMaxCPU for quiesceSamples consecutive intervals of quiesceInterval.
func waitQuiescent(ctx context.Context, container *dockerutil.Container) error {
	deadline := time.Now().Add(quiesceTimeout)
	var lastUsage uint64
	var lastTime time.Time
	quiet := 0
	for quiet < quiesceSamples {
		if time.Now().After(deadline) {
			return fmt.Errorf("CPU usage did not stay below %.1f%% for %v within %v", 100*quiesceMaxCPU, quiesceSamples*quiesceInterval, quiesceTimeout)
		}
		stats, err := container.Stats(ctx)
		if err != nil {
			return err
		}
		now := time.Now()
		usage := stats.CPUStats.CPUUsage.TotalUsage
		if !lastTime.IsZero() {
			if float64(usage-lastUsage) < quiesceMaxCPU*float64(now.Sub(lastTime).Nanoseconds()) {
				quiet++
			} else {
				quiet = 0
			}
		}
		lastUsage, lastTime = usage, now
		time.Sleep(quiesceInterval)
	}
	return nil
}

// loadKernel decodes the kernel from the state file data. If direct is true,
// it reads from the statefile.Reader directly, as runsc restore does;
// otherwise, it reads through a bufio.Reader.
func loadKernel(ctx context.Context, plat platform.Platform, data []byte, direct bool) (*kernel.Kernel, error) {
	sr, _, err := statefile.NewReader(io.NopCloser(bytes.NewReader(data)), nil)
	if err != nil {
		return nil, fmt.Errorf("statefile.NewReader: %w", err)
	}
	defer sr.Close()
	var r io.Reader = sr
	if !direct {
		r = bufio.NewReader(sr)
	}
	var fs cpuid.FeatureSet
	if _, err := state.Load(ctx, r, &fs); err != nil {
		return nil, fmt.Errorf("loading the CPUID feature set: %w (the benchmark must be built from the same tree as the runtime)", err)
	}
	k := &kernel.Kernel{Platform: plat}
	k.SetMemoryFile(pgalloc.MemoryFileFromContext(ctx))
	if _, err := state.Load(ctx, r, k); err != nil {
		return nil, fmt.Errorf("loading the kernel: %w (the benchmark must be built from the same tree as the runtime)", err)
	}
	return k, nil
}

// saveKernel encodes the CPUID feature set and the kernel to w through
// statefile.NewWriter using the input checkpoint's metadata.
func saveKernel(ctx context.Context, w io.Writer, k *kernel.Kernel, metadata map[string]string) error {
	wc, err := statefile.NewWriter(w, nil, metadata)
	if err != nil {
		return fmt.Errorf("statefile.NewWriter: %w", err)
	}
	fs := k.FeatureSet()
	if _, err := state.Save(ctx, wc, &fs); err != nil {
		return errors.Join(fmt.Errorf("saving the CPUID feature set: %w", err), wc.Close())
	}
	if _, err := state.Save(ctx, wc, k); err != nil {
		return errors.Join(fmt.Errorf("saving the kernel: %w", err), wc.Close())
	}
	return wc.Close()
}

// cpuTime runs fn with automatic garbage collection disabled, and returns the
// process CPU time it used. It collects garbage first, so that every call
// starts from the same heap state. Thus, ns/op and cpu-ns exclude garbage
// collection. The benchmark timer must be stopped on entry and remains stopped
// on return.
// B/op and allocs/op show the allocation pressure that causes it.
func cpuTime(b *testing.B, fn func() error) time.Duration {
	b.Helper()
	runtime.GC()
	gcPercent := debug.SetGCPercent(-1)
	cpu0 := processCPU(b)
	b.StartTimer()
	err := fn()
	b.StopTimer()
	cpu1 := processCPU(b)
	debug.SetGCPercent(gcPercent)
	if err != nil {
		b.Fatal(err)
	}
	return cpu1 - cpu0
}

// sampleHeapPeak samples the size of heap objects until the returned
// function is called, which returns the peak growth above the initial baseline.
func sampleHeapPeak() func() int64 {
	const name = "/memory/classes/heap/objects:bytes"
	samples := []metrics.Sample{{Name: name}}
	metrics.Read(samples)
	baseline := samples[0].Value.Uint64()
	done := make(chan struct{})
	result := make(chan int64, 1)
	go func() {
		peak := baseline
		ticker := time.NewTicker(100 * time.Microsecond)
		defer ticker.Stop()
		for {
			metrics.Read(samples)
			peak = max(peak, samples[0].Value.Uint64())
			select {
			case <-done:
				metrics.Read(samples)
				peak = max(peak, samples[0].Value.Uint64())
				result <- int64(peak - baseline)
				return
			case <-ticker.C:
			}
		}
	}()
	var stopped bool
	var delta int64
	return func() int64 {
		if !stopped {
			stopped = true
			close(done)
			delta = <-result
		}
		return delta
	}
}

// processCPU returns the user and system CPU time of the process.
func processCPU(b *testing.B) time.Duration {
	var ru unix.Rusage
	if err := unix.Getrusage(unix.RUSAGE_SELF, &ru); err != nil {
		b.Fatalf("getrusage: %v", err)
	}
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

// stubPlatform is the platform of decoded kernels. Memory managers create
// their address spaces when they are loaded, and the benchmark doesn't run
// tasks, so stubPlatform gives them address spaces without host resources.
type stubPlatform struct {
	*systrap.Systrap
}

// NewAddressSpace implements platform.Platform.NewAddressSpace.
func (stubPlatform) NewAddressSpace(platform.AddressSpaceOptions) (platform.AddressSpace, error) {
	return nopAddressSpace{}, nil
}

// nopAddressSpace is an address space that maps nothing.
type nopAddressSpace struct {
	platform.NoAddressSpaceIO
}

// MapFile implements platform.AddressSpace.MapFile.
func (nopAddressSpace) MapFile(hostarch.Addr, memmap.File, memmap.FileRange, hostarch.AccessType, bool) error {
	return nil
}

// Unmap implements platform.AddressSpace.Unmap.
func (nopAddressSpace) Unmap(hostarch.Addr, uint64) {}

// Release implements platform.AddressSpace.Release.
func (nopAddressSpace) Release() {}

// PreFork implements platform.AddressSpace.PreFork.
func (nopAddressSpace) PreFork() {}

// PostFork implements platform.AddressSpace.PostFork.
func (nopAddressSpace) PostFork() {}

// UserModifiedGS implements platform.AddressSpace.UserModifiedGS.
func (nopAddressSpace) UserModifiedGS(pkgcontext.Context, platform.MemoryManager) error {
	return nil
}

// countingWriter counts the bytes written to it.
type countingWriter struct {
	n int64
}

// Write implements io.Writer.Write.
func (w *countingWriter) Write(p []byte) (int, error) {
	w.n += int64(len(p))
	return len(p), nil
}

// Make sure that the kernel's state types are registered.
var _ = boot.VersionKey

func TestMain(m *testing.M) {
	harness.Init()
	// Loading tasks' floating point state uses the host's CPUID,
	// expected by the kernel load machinery.
	cpuid.Initialize()
	// Initialize the FD notifier as Kernel.LoadFrom does, since the
	// checkpoint may not have any host FDs to register with it.
	fdnotifier.Pause()
	fdnotifier.Resume()
	os.Exit(m.Run())
}
