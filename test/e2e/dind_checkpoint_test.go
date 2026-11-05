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

package integration

import (
	"context"
	"flag"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/pkg/test/testutil"
)

var (
	dindCheckpoint    = flag.Bool("dind-checkpoint", false, "run the legacy-iptables DinD checkpoint profile; see test/e2e/dind_checkpoint.txt")
	dindUserlandProxy = flag.Bool("dind-userland-proxy", true, "enable the inner Docker userland proxy; disabling it requires per-interface route_localnet support")
)

// The daemon and its container images/data live on the sandbox's tmpfs. The
// host Docker daemon supplies only the outer container and its checkpoint API.
const dindDaemon = `set -eu
mkdir -p /cr-bin /var/lib/docker/cr-evidence
for family in iptables ip6tables; do
  for suffix in '' -save -restore; do
    legacy=$(command -v "${family}-legacy${suffix}")
    ln -s "$legacy" "/cr-bin/${family}${suffix}"
  done
done
export PATH="/cr-bin:$PATH"
iptables --version | grep -q legacy
echo 1 > /proc/sys/net/ipv4/ip_forward
exec dockerd --host=unix:///var/run/docker.sock --data-root=/var/lib/docker \
  --storage-driver=vfs --feature containerd-snapshotter=false \
  --iptables=true --ip6tables=false --userland-proxy=%t
`

// Neither nc process reconnects. Every progress update follows an echoed
// payload on the original connection, with both process IDs recorded.
const dindClient = `set -eu
mkfifo /evidence/send /evidence/receive
nc server 7000 < /evidence/send > /evidence/receive &
nc_pid=$!
exec 3>/evidence/send
exec 4</evidence/receive
counter=0
while true; do
  counter=$((counter + 1))
  expected="checkpoint-payload-$counter"
  printf '%s\n' "$expected" >&3
  IFS= read -r reply <&4
  test "$reply" = "$expected"
  printf '%s %s %s\n' "$$" "$nc_pid" "$counter" > /evidence/progress.tmp
  mv /evidence/progress.tmp /evidence/progress
  sleep 0.1
done
`

func TestDinDCheckpointRestore(t *testing.T) {
	if !*dindCheckpoint {
		t.Skip("enable -dind-checkpoint after configuring the legacy DinD profile")
	}
	if !testutil.IsCheckpointSupported() || !dockerutil.IsRestoreSupported() {
		t.Fatal("the selected DinD profile requires checkpoint support and an outer Docker version supported by dockerutil.IsRestoreSupported (currently <=27)")
	}
	dockerutil.EnsureDockerExperimentalEnabled()
	for _, leaveRunning := range []bool{false, true} {
		t.Run(fmt.Sprintf("leave-running-%t", leaveRunning), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()
			outer := dockerutil.MakeContainer(ctx, t)
			t.Cleanup(func() {
				cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), time.Minute)
				defer cleanupCancel()
				if t.Failed() {
					if logs, err := outer.Logs(cleanupCtx); err == nil {
						t.Logf("outer dockerd logs:\n%s", logs)
					}
				}
				outer.CleanUp(cleanupCtx)
			})
			isGVisor, err := dockerutil.IsGVisorRuntime(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := outer.Spawn(ctx, dockerutil.RunOpts{
				Image: "moby", Entrypoint: []string{"/bin/sh"},
				CapAdd: []string{"ALL"}, Privileged: !isGVisor,
				Env:   []string{"DOCKER_HOST=unix:///var/run/docker.sock"},
				Tmpfs: map[string]string{"/var/lib/docker": "exec"},
			}, "-c", fmt.Sprintf(dindDaemon, *dindUserlandProxy)); err != nil {
				t.Fatal(err)
			}
			command := func(args ...string) string {
				t.Helper()
				out, err := outer.Exec(ctx, dockerutil.ExecOpts{}, args...)
				if err != nil {
					t.Fatalf("exec %q: %v\n%s", args, err, out)
				}
				return strings.TrimSpace(out)
			}
			wait := func(args ...string) {
				t.Helper()
				deadline := time.Now().Add(defaultWait)
				for {
					attemptCtx, attemptCancel := context.WithTimeout(ctx, 5*time.Second)
					out, err := outer.Exec(attemptCtx, dockerutil.ExecOpts{}, args...)
					attemptCancel()
					if err == nil {
						return
					}
					statusCtx, statusCancel := context.WithTimeout(ctx, 5*time.Second)
					status, statusErr := outer.Status(statusCtx)
					statusCancel()
					if statusErr != nil {
						t.Fatalf("inspect outer dockerd while waiting for %q: %v", args, statusErr)
					}
					if !status.Running {
						t.Fatalf("outer dockerd exited (code %d) while waiting for %q: %v\n%s", status.ExitCode, args, err, out)
					}
					if time.Now().After(deadline) || ctx.Err() != nil {
						t.Fatalf("waiting for %q: %v\n%s", args, err, out)
					}
					time.Sleep(100 * time.Millisecond)
				}
			}
			t.Logf("starting inner dockerd: userland-proxy=%t, executable tmpfs/vfs", *dindUserlandProxy)
			wait("docker", "info")
			t.Logf("Docker: %s; backend: %s; storage: %s", command("docker", "version", "--format", "{{.Server.Version}}"), command("/cr-bin/iptables", "--version"), command("docker", "info", "--format", "{{.Driver}}"))
			command("docker", "load", "-i", "/docker-images/busybox.tar")
			t.Logf("inner workload image: %s", command("docker", "image", "inspect", "busybox:latest", "--format", "{{.Id}}"))
			command("docker", "network", "create", "cr-net")
			command("docker", "run", "-d", "--name", "server", "--network", "cr-net", "-p", "18080:8080", "busybox:latest", "sh", "-c",
				"mkdir -p /www; echo checkpoint-ready > /www/index.html; httpd -p 8080 -h /www; exec nc -l -p 7000 -e cat")
			// Inspect the listening socket without consuming its single accept.
			wait("docker", "exec", "server", "sh", "-c", "netstat -lnt | grep -q ':7000 '")
			command("docker", "run", "-d", "--name", "client", "--network", "cr-net", "-v", "/var/lib/docker/cr-evidence:/evidence", "busybox:latest", "sh", "-c", dindClient)
			progress := func() (string, int) {
				t.Helper()
				wait("test", "-s", "/var/lib/docker/cr-evidence/progress")
				fields := strings.Fields(command("cat", "/var/lib/docker/cr-evidence/progress"))
				if len(fields) != 3 {
					t.Fatalf("invalid progress: %q", fields)
				}
				sequence, err := strconv.Atoi(fields[2])
				if err != nil {
					t.Fatal(err)
				}
				return fields[0] + "/" + fields[1], sequence
			}
			identity, _ := progress()
			advance := func() {
				t.Helper()
				_, baseline := progress()
				deadline := time.Now().Add(defaultWait)
				for {
					id, sequence := progress()
					if id != identity {
						t.Fatalf("client/connection process changed: %s -> %s", identity, id)
					}
					if sequence > baseline+2 {
						return
					}
					if time.Now().After(deadline) || ctx.Err() != nil {
						t.Fatalf("TCP stream stalled at %d", sequence)
					}
					time.Sleep(100 * time.Millisecond)
				}
			}
			chainCounters := regexp.MustCompile(`\[\d+:\d+\]`)
			rules := func() string {
				var lines []string
				for _, line := range strings.Split(command("/cr-bin/iptables-save"), "\n") {
					if !strings.HasPrefix(line, "#") {
						lines = append(lines, line)
					}
				}
				return chainCounters.ReplaceAllString(strings.Join(lines, "\n"), "[0:0]")
			}
			inspect := func() string {
				return command("docker", "inspect", "--format", "{{.Id}} {{.State.Pid}} {{json .NetworkSettings.Networks}}", "server", "client")
			}
			checkNetwork := func() {
				t.Helper()
				if got := command("wget", "-qO-", "http://127.0.0.1:18080"); got != "checkpoint-ready" {
					t.Fatalf("published-port response: %q", got)
				}
				command("docker", "exec", "client", "nslookup", "server")
			}
			advance()
			checkNetwork()
			for round := 0; round < 2; round++ {
				beforeRules, beforeContainers := rules(), inspect()
				name := fmt.Sprintf("dind-%d", round)
				t.Logf("round %d: checkpoint, leave-running=%t", round+1, leaveRunning)
				if leaveRunning {
					if err := outer.CheckpointResume(ctx, name); err != nil {
						t.Fatal(err)
					}
					advance()
					// Stop the source before restoring its network identity.
					if err := outer.Kill(ctx); err != nil {
						t.Fatal(err)
					}
				} else if err := outer.Checkpoint(ctx, name); err != nil {
					t.Fatal(err)
				}
				if err := outer.WaitTimeout(ctx, defaultWait); err != nil {
					t.Fatal(err)
				}
				t.Logf("round %d: restore", round+1)
				if err := outer.Restore(ctx, name); err != nil {
					t.Fatal(err)
				}
				wait("docker", "info")
				advance()
				if got := inspect(); got != beforeContainers {
					t.Fatalf("container identity changed:\nbefore: %s\nafter: %s", beforeContainers, got)
				}
				if got := rules(); got != beforeRules {
					t.Fatalf("iptables changed:\nbefore:\n%s\nafter:\n%s", beforeRules, got)
				}
				checkNetwork()
				network := fmt.Sprintf("cr-new-%d", round)
				command("docker", "network", "create", network)
				command("docker", "network", "connect", network, "server")
				command("docker", "run", "--rm", "--network", network, "busybox:latest", "ping", "-c", "1", "-W", "3", "server")
				command("docker", "network", "disconnect", network, "server")
				command("docker", "network", "rm", network)
				advance()
				t.Logf("round %d: restored connection, identities, rules and network operations verified", round+1)
			}
		})
	}
}
