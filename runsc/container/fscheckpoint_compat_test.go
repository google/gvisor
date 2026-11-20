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

package container

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/sentry/fscheckpoint"
	fspb "gvisor.dev/gvisor/pkg/sentry/fscheckpoint/fscheckpoint_proto_go_proto"
	"gvisor.dev/gvisor/pkg/sentry/state/checkpointfiles"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/sandbox"
	"gvisor.dev/gvisor/runsc/specutils"
)

var (
	fscheckpointCorpusDir   = flag.String("fscheckpoint-corpus-dir", "", "Path to historical fscheckpoint corpus directory.")
	fscheckpointGenerateDir = flag.String("fscheckpoint-generate-dir", "", "Directory where a generated fscheckpoint corpus snapshot should be written.")
	fscheckpointRunscBin    = flag.String("fscheckpoint-runsc-bin", "", "Optional path to a specific runsc binary to use when generating a corpus snapshot.")
)

type snapshotMetadata struct {
	CommitTimestampUnix int64      `json:"commit_timestamp_unix"`
	CommitHash          string     `json:"commit_hash,omitempty"`
	RunscVersion        string     `json:"runsc_version,omitempty"`
	ManifestVersion     uint64     `json:"manifest_version,omitempty"`
	FSTreeArgs          [][]string `json:"fs_tree_args,omitempty"`
}

func readManifestVersion(manifestPath string) (uint64, error) {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return 0, err
	}
	var pb fspb.Manifest
	if err := proto.Unmarshal(data, &pb); err != nil {
		return 0, err
	}
	return pb.Version, nil
}

type snapshotEntry struct {
	path     string
	dirName  string
	metadata snapshotMetadata
}

func setupFSCheckpointContainerRoots(containerSpecs []*specs.Spec, ids []string) (func(), error) {
	var cleanupSpecRoots cleanup.Cleanup
	defer cleanupSpecRoots.Clean()

	appSrc, err := testutil.FindFile("test/cmd/test_app/test_app")
	if err != nil {
		return nil, fmt.Errorf("error finding test_app: %w", err)
	}

	for i, spec := range containerSpecs {
		contRootPath, err := os.MkdirTemp(testutil.TmpDir(), fmt.Sprintf("%s-root", ids[i]))
		if err != nil {
			return nil, fmt.Errorf("error creating root directory for container %d: %w", i, err)
		}
		cleanupSpecRoots.Add(func() { os.RemoveAll(contRootPath) })
		spec.Root.Path = contRootPath
		spec.Root.Readonly = false

		appDst := filepath.Join(contRootPath, "app")
		if err := copyFile(appSrc, appDst); err != nil {
			return nil, fmt.Errorf("error copying app binary from %q to %q: %w", appSrc, appDst, err)
		}
	}
	return cleanupSpecRoots.Release(), nil
}

func detectRunscVersion(t *testing.T, runscBin string) string {
	t.Helper()
	if runscBin == "" {
		runscBin = specutils.ExePath
	}
	if runscBin == "" {
		t.Fatal("No runsc binary configured (neither -fscheckpoint-runsc-bin nor specutils.ExePath is set)")
	}
	out, err := exec.Command(runscBin, "--version").Output()
	if err != nil {
		t.Fatalf("Failed to run %q --version: %v", runscBin, err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "runsc version ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "runsc version "))
		}
	}
	return strings.TrimSpace(string(out))
}

func generateWithRunscBinary(t *testing.T, conf *config.Config, runscBin string, saveSpecs []*specs.Spec, ids []string, fsTreeArgs [][]string, outDir string) {
	t.Helper()

	rootDir, cleanupRootDir, err := testutil.SetupRootDir()
	if err != nil {
		t.Fatalf("Error creating root directory: %v", err)
	}
	defer cleanupRootDir()

	var env []string
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, "GVISOR_SIDECAR_BINARIES_DIR=") {
			env = append(env, e)
		}
	}
	sidecarDir := filepath.Join(filepath.Dir(runscBin), "gvisor-bin")
	if fi, err := os.Stat(sidecarDir); err == nil && fi.IsDir() {
		env = append(env, "GVISOR_SIDECAR_BINARIES_DIR="+sidecarDir)
	}

	runRunsc := func(args ...string) error {
		baseArgs := []string{
			"--root=" + rootDir,
			"--network=none",
			"--platform=" + conf.Platform,
			"--overlay2=root:self",
			"--TESTONLY-unsafe-nonroot=true",
		}
		logFile, err := os.CreateTemp(testutil.TmpDir(), "runsc-cmd-*.log")
		if err != nil {
			return fmt.Errorf("creating log file: %w", err)
		}
		logPath := logFile.Name()
		defer os.Remove(logPath)

		cmd := exec.Command(runscBin, append(baseArgs, args...)...)
		cmd.Env = env
		cmd.Stdout = logFile
		cmd.Stderr = logFile
		runErr := cmd.Run()
		_ = logFile.Close()
		if runErr != nil {
			out, _ := os.ReadFile(logPath)
			return fmt.Errorf("runsc %v failed: %v\noutput:\n%s", args, runErr, string(out))
		}
		return nil
	}

	for i, spec := range saveSpecs {
		bundleDir, cleanupBundle, err := testutil.SetupBundleDir(spec)
		if err != nil {
			t.Fatalf("Error setting up bundle for container %d: %v", i, err)
		}
		defer cleanupBundle()

		id := ids[i]
		if err := runRunsc("create", "--bundle="+bundleDir, id); err != nil {
			t.Fatalf("Error creating container %d: %v", i, err)
		}
		defer func() {
			_ = runRunsc("delete", "--force", id)
		}()
		if err := runRunsc("start", id); err != nil {
			t.Fatalf("Error starting container %d: %v", i, err)
		}
	}

	for i := range saveSpecs {
		execArgs := append([]string{"exec", ids[i], "/app", "fsTreeCreate"}, fsTreeArgs[i]...)
		if err := runRunsc(execArgs...); err != nil {
			t.Fatalf("Error populating checkpoint filesystem for container %d: %v", i, err)
		}
	}

	if err := os.RemoveAll(outDir); err != nil {
		t.Fatalf("Error clearing output directory %q: %v", outDir, err)
	}
	if err := os.MkdirAll(outDir, 0755); err != nil {
		t.Fatalf("Error creating output directory %q: %v", outDir, err)
	}

	if err := runRunsc("fscheckpoint", "--image-path="+outDir, "--path="+fscheckpoint.AllTmpfsPath, ids[0]); err != nil {
		t.Fatalf("Error saving filesystem checkpoint: %v", err)
	}
}

func generateFSCheckpointSnapshot(t *testing.T, conf *config.Config, outDir string, runscBin string) snapshotMetadata {
	t.Helper()

	const (
		rootName = "root-container"
		subName  = "sub-container"
	)

	conf.Overlay2.Set("root:self")

	testAppSleepArgv := []string{"/app", "reaper"}
	saveSpecs, ids := createSpecs(testAppSleepArgv, testAppSleepArgv)
	saveSpecs[0].Annotations[specutils.ContainerdContainerNameAnnotation] = rootName
	saveSpecs[1].Annotations[specutils.ContainerdContainerNameAnnotation] = subName

	cleanupRoots, err := setupFSCheckpointContainerRoots(saveSpecs, ids)
	if err != nil {
		t.Fatalf("Error setting up container roots: %v", err)
	}
	defer cleanupRoots()

	fsTreeArgs := [][]string{
		{"--depth=10", "--file-per-level=10", "--file-size=65537", "--create-symlink", "--add-empty-files", "--target-dir=/", "--seed=42"},
		{"--depth=10", "--file-per-level=10", "--file-size=65537", "--create-symlink", "--add-empty-files", "--target-dir=/", "--seed=43"},
	}

	if runscBin != "" {
		generateWithRunscBinary(t, conf, runscBin, saveSpecs, ids, fsTreeArgs, outDir)
	} else {
		conts, cleanupConts, err := startContainers(conf, saveSpecs, ids)
		if err != nil {
			t.Fatalf("Error starting containers: %v", err)
		}
		defer cleanupConts()

		for i := range conts {
			if ws, err := execute(conf, conts[i], "/app", append([]string{"fsTreeCreate"}, fsTreeArgs[i]...)...); err != nil || ws != 0 {
				t.Fatalf("Error populating checkpoint filesystem for container %d, ws: %v, err: %v", i, ws, err)
			}
		}

		if err := os.MkdirAll(outDir, 0755); err != nil {
			t.Fatalf("Error creating output directory %q: %v", outDir, err)
		}

		if err := conts[0].FSSave(conf, outDir, sandbox.FSSaveOpts{
			ExitAfterSaving: true,
			Paths:           []string{fscheckpoint.AllTmpfsPath},
		}); err != nil {
			t.Fatalf("Error saving filesystem checkpoint: %v", err)
		}

		ws, err := conts[0].Wait()
		if err != nil {
			t.Fatalf("Error waiting for checkpointed sandbox: %v", err)
		}
		if got, want := ws, unix.WaitStatus(0); got != want {
			t.Fatalf("Wait() = %v, want %v", got, want)
		}
	}

	commitTime := time.Now().Unix()
	commitHash := "unknown"
	if out, err := exec.Command("git", "log", "-1", "--format=%ct").Output(); err == nil {
		if ct, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64); err == nil && ct > 0 {
			commitTime = ct
		}
	}
	if out, err := exec.Command("git", "rev-parse", "--short=8", "HEAD").Output(); err == nil {
		commitHash = strings.TrimSpace(string(out))
	}

	manifestPath := filepath.Join(outDir, checkpointfiles.FSCheckpointManifestFileName)
	manifestVersion, err := readManifestVersion(manifestPath)
	if err != nil {
		t.Fatalf("Error reading generated manifest %q: %v", manifestPath, err)
	}

	meta := snapshotMetadata{
		CommitTimestampUnix: commitTime,
		CommitHash:          commitHash,
		RunscVersion:        detectRunscVersion(t, runscBin),
		ManifestVersion:     manifestVersion,
		FSTreeArgs:          fsTreeArgs,
	}

	metaBytes, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		t.Fatalf("Error marshaling metadata: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "metadata.json"), metaBytes, 0644); err != nil {
		t.Fatalf("Error writing metadata.json: %v", err)
	}

	return meta
}

func verifyFSCheckpointRestore(t *testing.T, conf *config.Config, imagePath string, meta snapshotMetadata) {
	t.Helper()

	const (
		rootName = "root-container"
		subName  = "sub-container"
	)

	manifestPath := filepath.Join(imagePath, checkpointfiles.FSCheckpointManifestFileName)
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("Failed to read manifest: %v", err)
	}
	var manifestProto fspb.Manifest
	if err := proto.Unmarshal(manifestData, &manifestProto); err != nil {
		t.Fatalf("Failed to unmarshal manifest proto: %v", err)
	}
	t.Logf("Restoring fscheckpoint generated by runsc version: %q, manifest version: %d", manifestProto.RunscVersion, manifestProto.Version)

	conf.Overlay2.Set("root:self")

	testAppSleepArgv := []string{"/app", "reaper"}
	restoreSpecs, restoreIDs := createSpecs(testAppSleepArgv, testAppSleepArgv)
	restoreSpecs[0].Annotations[specutils.ContainerdContainerNameAnnotation] = rootName
	restoreSpecs[1].Annotations[specutils.ContainerdContainerNameAnnotation] = subName

	cleanupRoots, err := setupFSCheckpointContainerRoots(restoreSpecs, restoreIDs)
	if err != nil {
		t.Fatalf("Error setting up restore container roots: %v", err)
	}
	defer cleanupRoots()

	restoreConts, cleanupConts, err := startContainersWithArgs(conf, restoreSpecs, restoreIDs, func(i int, contArgs *Args) {
		if i == 0 {
			contArgs.FSRestoreImagePaths = []string{imagePath}
		}
	})
	if err != nil {
		t.Fatalf("Error starting restore containers: %v", err)
	}
	defer cleanupConts()

	fsTreeArgs := meta.FSTreeArgs
	if len(fsTreeArgs) < 2 {
		fsTreeArgs = [][]string{
			{"--depth=10", "--file-per-level=10", "--file-size=65537", "--create-symlink", "--add-empty-files", "--target-dir=/", "--seed=42"},
			{"--depth=10", "--file-per-level=10", "--file-size=65537", "--create-symlink", "--add-empty-files", "--target-dir=/", "--seed=43"},
		}
	}

	for i := range restoreConts {
		if ws, err := execute(conf, restoreConts[i], "/app", append([]string{"fsTreeVerify"}, fsTreeArgs[i]...)...); err != nil || ws != 0 {
			t.Fatalf("Error verifying checkpointed filesystem for container %d, ws: %v, err: %v", i, ws, err)
		}
	}

	for i, cont := range restoreConts {
		if err := cont.WaitFSRestore(); err != nil {
			t.Errorf("Error waiting for FS restore for container %d: %v", i, err)
		}
	}
}

// TestFSCheckpointCorpusGenerate creates a fresh fscheckpoint corpus snapshot.
func TestFSCheckpointCorpusGenerate(t *testing.T) {
	outDir := *fscheckpointGenerateDir
	if outDir == "" {
		outDir = os.Getenv("FSCHECKPOINT_GENERATE_DIR")
	}
	if outDir == "" {
		t.Fatal("No -fscheckpoint-generate-dir or FSCHECKPOINT_GENERATE_DIR specified.")
	}

	runscBin := *fscheckpointRunscBin
	if runscBin == "" {
		runscBin = os.Getenv("FSCHECKPOINT_RUNSC_BIN")
	}

	conf := testutil.TestConfig(t)
	rootDir, cleanupRoot, err := testutil.SetupRootDir()
	if err != nil {
		t.Fatalf("Error creating root dir: %v", err)
	}
	defer cleanupRoot()
	conf.RootDir = rootDir

	generateFSCheckpointSnapshot(t, conf, outDir, runscBin)
	t.Logf("Successfully generated fscheckpoint corpus snapshot at %s", outDir)
}

func loadCorpusSnapshots(corpusDir string) ([]snapshotEntry, error) {
	entries, err := os.ReadDir(corpusDir)
	if err != nil {
		return nil, err
	}

	var snapshots []snapshotEntry
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dirPath := filepath.Join(corpusDir, entry.Name())
		metaPath := filepath.Join(dirPath, "metadata.json")
		manifestPath := filepath.Join(dirPath, checkpointfiles.FSCheckpointManifestFileName)
		if _, err := os.Stat(manifestPath); err != nil {
			continue
		}

		var meta snapshotMetadata
		if data, err := os.ReadFile(metaPath); err == nil {
			_ = json.Unmarshal(data, &meta)
		}
		if meta.CommitTimestampUnix == 0 {
			parts := strings.Split(entry.Name(), "_")
			if len(parts) > 0 {
				if parsed, err := time.Parse("20060102-150405", parts[0]); err == nil {
					meta.CommitTimestampUnix = parsed.Unix()
				}
			}
		}
		if meta.CommitTimestampUnix <= 0 {
			continue
		}
		if meta.ManifestVersion == 0 {
			if ver, err := readManifestVersion(manifestPath); err == nil {
				meta.ManifestVersion = ver
			}
		}

		snapshots = append(snapshots, snapshotEntry{
			path:     dirPath,
			dirName:  entry.Name(),
			metadata: meta,
		})
	}

	sort.Slice(snapshots, func(i, j int) bool {
		if snapshots[i].metadata.CommitTimestampUnix != snapshots[j].metadata.CommitTimestampUnix {
			return snapshots[i].metadata.CommitTimestampUnix < snapshots[j].metadata.CommitTimestampUnix
		}
		return snapshots[i].dirName < snapshots[j].dirName
	})

	return snapshots, nil
}

// TestFSCheckpointCompatibility verifies backward compatibility by restoring
// historical snapshots (latest, date-based buckets up to 12 months old, and
// per-manifest-version snapshots) on HEAD.
func TestFSCheckpointCompatibility(t *testing.T) {
	corpusDir := *fscheckpointCorpusDir
	if corpusDir == "" {
		corpusDir = os.Getenv("FSCHECKPOINT_CORPUS_DIR")
	}
	if corpusDir == "" {
		corpusDir = "../../compatibility_testing"
	}

	if _, err := os.Stat(corpusDir); os.IsNotExist(err) {
		t.Fatalf("Corpus directory %q does not exist", corpusDir)
	}

	snapshots, err := loadCorpusSnapshots(corpusDir)
	if err != nil {
		t.Fatalf("Failed to read corpus directory %q: %v", corpusDir, err)
	}

	if len(snapshots) == 0 {
		t.Fatalf("No valid snapshots found in corpus directory %q", corpusDir)
	}

	t.Logf("Found %d snapshots in corpus %q", len(snapshots), corpusDir)

	conf := testutil.TestConfig(t)
	rootDir, cleanupRoot, err := testutil.SetupRootDir()
	if err != nil {
		t.Fatalf("Error creating root dir: %v", err)
	}
	defer cleanupRoot()
	conf.RootDir = rootDir

	now := time.Now()

	t.Run("latest", func(t *testing.T) {
		latest := snapshots[len(snapshots)-1]
		t.Logf("Testing latest snapshot: %s (commit %s, timestamp %s)",
			latest.dirName, latest.metadata.CommitHash, time.Unix(latest.metadata.CommitTimestampUnix, 0).Format(time.RFC3339))
		verifyFSCheckpointRestore(t, conf, latest.path, latest.metadata)
	})

	testBuckets := []struct {
		name          string
		monthsAgo     int
		minCorpusDays float64
		maxMatchDiff  time.Duration
	}{
		{
			name:          "1-month-old",
			monthsAgo:     1,
			minCorpusDays: 25,
			maxMatchDiff:  10 * 24 * time.Hour,
		},
		{
			name:          "2-month-old",
			monthsAgo:     2,
			minCorpusDays: 55,
			maxMatchDiff:  15 * 24 * time.Hour,
		},
		{
			name:          "3-month-old",
			monthsAgo:     3,
			minCorpusDays: 85,
			maxMatchDiff:  15 * 24 * time.Hour,
		},
		{
			name:          "6-month-old",
			monthsAgo:     6,
			minCorpusDays: 175,
			maxMatchDiff:  20 * 24 * time.Hour,
		},
		{
			name:          "9-month-old",
			monthsAgo:     9,
			minCorpusDays: 265,
			maxMatchDiff:  20 * 24 * time.Hour,
		},
		{
			name:          "12-month-old",
			monthsAgo:     12,
			minCorpusDays: 355,
			maxMatchDiff:  20 * 24 * time.Hour,
		},
	}

	for _, bucket := range testBuckets {
		t.Run(bucket.name, func(t *testing.T) {
			targetTime := now.AddDate(0, -bucket.monthsAgo, 0)
			var bestMatch *snapshotEntry
			var bestDiff time.Duration = 1<<63 - 1

			for i := range snapshots {
				snapshotTime := time.Unix(snapshots[i].metadata.CommitTimestampUnix, 0)
				diff := snapshotTime.Sub(targetTime)
				if diff < 0 {
					diff = -diff
				}
				if diff < bestDiff {
					bestDiff = diff
					bestMatch = &snapshots[i]
				}
			}

			oldestTime := time.Unix(snapshots[0].metadata.CommitTimestampUnix, 0)
			daysOld := now.Sub(oldestTime).Hours() / 24
			if daysOld < bucket.minCorpusDays {
				t.Skipf("Oldest snapshot in corpus is only %.1f days old (< %.0f days); skipping %s compatibility test.",
					daysOld, bucket.minCorpusDays, bucket.name)
			}

			if bestMatch == nil || bestDiff > bucket.maxMatchDiff {
				t.Skipf("No snapshot close to %d month(s) old found (best diff: %v); skipping.", bucket.monthsAgo, bestDiff)
			}

			t.Logf("Testing %s snapshot: %s (commit %s, age %.1f days)",
				bucket.name, bestMatch.dirName, bestMatch.metadata.CommitHash, now.Sub(time.Unix(bestMatch.metadata.CommitTimestampUnix, 0)).Hours()/24)
			verifyFSCheckpointRestore(t, conf, bestMatch.path, bestMatch.metadata)
		})
	}

	versionCutoff := now.Add(-380 * 24 * time.Hour)
	latestByVersion := make(map[uint64]*snapshotEntry)
	for i := range snapshots {
		ver := snapshots[i].metadata.ManifestVersion
		if ver == 0 {
			continue
		}
		if time.Unix(snapshots[i].metadata.CommitTimestampUnix, 0).Before(versionCutoff) {
			continue
		}
		latestByVersion[ver] = &snapshots[i]
	}

	var versions []uint64
	for ver := range latestByVersion {
		versions = append(versions, ver)
	}
	sort.Slice(versions, func(i, j int) bool { return versions[i] < versions[j] })

	for _, ver := range versions {
		snap := latestByVersion[ver]
		t.Run(fmt.Sprintf("manifest-v%d", ver), func(t *testing.T) {
			t.Logf("Testing manifest version %d snapshot: %s (commit %s, age %.1f days)",
				ver, snap.dirName, snap.metadata.CommitHash, now.Sub(time.Unix(snap.metadata.CommitTimestampUnix, 0)).Hours()/24)
			verifyFSCheckpointRestore(t, conf, snap.path, snap.metadata)
		})
	}
}
