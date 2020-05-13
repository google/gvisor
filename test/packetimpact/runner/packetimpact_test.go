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

// The runner starts docker containers and networking for a packetimpact test.
package packetimpact_test

import (
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/test/packetimpact/netdevs"
)

// stringList implements flag.Value.
type stringList []string

// String implements flag.Value.String.
func (l *stringList) String() string {
	return strings.Join(*l, ",")
}

// Set implements flag.Value.Set.
func (l *stringList) Set(value string) error {
	*l = append(*l, value)
	return nil
}

var (
	dutPlatform     = flag.String("dut_platform", "", "either \"linux\" or \"netstack\"")
	testbenchBinary = flag.String("testbench_binary", "", "path to the testbench binary")
	tshark          = flag.Bool("tshark", false, "use more verbose tshark in logs instead of tcpdump")
	extraTestArgs   = stringList{}
	expectFailure   = flag.Bool("expect_failure", false, "expect that the test will fail when run")

	dutAddr       = net.IPv4(0, 0, 0, 10)
	testbenchAddr = net.IPv4(0, 0, 0, 20)
)

const ctrlPort = "40000"

// logger implements testutil.Logger.
//
// Labels logs based on their source and formats multi-line logs.
type logger string

// Name implements testutil.Logger.Name.
func (l logger) Name() string {
	return string(l)
}

// Logf implements testutil.Logger.Logf.
func (l logger) Logf(format string, args ...interface{}) {
	lines := strings.Split(fmt.Sprintf(format, args...), "\n")
	log.Printf("%s: %s", l, lines[0])
	for _, line := range lines[1:] {
		log.Printf("%*s  %s", len(l), "", line)
	}
}

func TestOne(t *testing.T) {
	flag.Var(&extraTestArgs, "extra_test_arg", "extra arguments to pass to the testbench")
	flag.Parse()
	if *dutPlatform != "linux" && *dutPlatform != "netstack" {
		t.Fatal("--dut_platform should be either linux or netstack")
	}
	if *testbenchBinary == "" {
		t.Fatal("--testbench_binary is missing")
	}
	if *dutPlatform == "netstack" {
		if _, err := dockerutil.RuntimePath(); err != nil {
			t.Fatal("--runtime is missing or invalid with --dut_platform=netstack:", err)
		}
	}
	dockerutil.EnsureSupportedDockerVersion()

	// Create the networks needed for the test. One control network is needed for
	// the gRPC control packets and one test network on which to transmit the test
	// packets.
	ctrlNet := dockerutil.NewDockerNetwork(logger("ctrlNet"))
	testNet := dockerutil.NewDockerNetwork(logger("testNet"))
	for _, dn := range []*dockerutil.DockerNetwork{ctrlNet, testNet} {
		for {
			if err := createDockerNetwork(dn); err != nil {
				t.Log("creating docker network:", err)
				const wait = 100 * time.Millisecond
				t.Logf("sleeping %s and will try creating docker network again", wait)
				// This can fail if another docker network claimed the same IP so we'll
				// just try again.
				time.Sleep(wait)
				continue
			}
			break
		}
		defer func(dn *dockerutil.DockerNetwork) {
			if err := dn.Cleanup(); err != nil {
				t.Errorf("unable to cleanup container %s: %s", dn.Name, err)
			}
		}(dn)
	}

	runOpts := dockerutil.RunOpts{
		Image:      "packetimpact",
		CapAdd:     []string{"NET_ADMIN"},
		Extra:      []string{"--sysctl", "net.ipv6.conf.all.disable_ipv6=0", "--rm"},
		Foreground: true,
		Pty:        func(_ *exec.Cmd, _ *os.File) {},
	}

	// Create the Docker container for the DUT.
	dut := dockerutil.MakeDocker(logger("dut"))
	if *dutPlatform == "linux" {
		dut.Runtime = ""
	}

	const containerPosixServerBinary = "/packetimpact/posix_server"
	dut.CopyFiles("/packetimpact", "/test/packetimpact/dut/posix_server")

	if err := dut.Create(runOpts, containerPosixServerBinary, "--ip=0.0.0.0", "--port="+ctrlPort); err != nil {
		t.Fatalf("unable to create container %s: %s", dut.Name, err)
	}
	defer dut.CleanUp()

	// Add ctrlNet as eth1 and testNet as eth2.
	const testNetDev = "eth2"
	if err := addNetworks(dut, dutAddr, []*dockerutil.DockerNetwork{ctrlNet, testNet}); err != nil {
		t.Fatal(err)
	}

	if err := dut.Start(); err != nil {
		t.Fatalf("unable to start container %s: %s", dut.Name, err)
	}

	if _, err := dut.WaitForOutput("Server listening.*\n", 60*time.Second); err != nil {
		t.Fatalf("%s on container %s never listened: %s", containerPosixServerBinary, dut.Name, err)
	}

	dutTestDevice, dutDeviceInfo, err := deviceByIP(dut, addressInSubnet(dutAddr, *testNet.Subnet))
	if err != nil {
		t.Fatal(err)
	}

	remoteMAC := dutDeviceInfo.MAC
	remoteIPv6 := dutDeviceInfo.IPv6Addr
	// Netstack as DUT doesn't assign IPv6 addresses automatically so do it if
	// needed.
	if remoteIPv6 == nil {
		if _, err := dut.Exec(dockerutil.RunOpts{}, "ip", "addr", "add", netdevs.MACToIP(remoteMAC).String(), "scope", "link", "dev", dutTestDevice); err != nil {
			t.Fatalf("unable to ip addr add on container %s: %s", dut.Name, err)
		}
		// Now try again, to make sure that it worked.
		_, dutDeviceInfo, err = deviceByIP(dut, addressInSubnet(dutAddr, *testNet.Subnet))
		if err != nil {
			t.Fatal(err)
		}
		remoteIPv6 = dutDeviceInfo.IPv6Addr
		if remoteIPv6 == nil {
			t.Fatal("unable to set IPv6 address on container", dut.Name)
		}
	}

	// Create the Docker container for the testbench.
	testbench := dockerutil.MakeDocker(logger("testbench"))
	testbench.Runtime = "" // The testbench always runs on Linux.

	tbb := path.Base(*testbenchBinary)
	containerTestbenchBinary := "/packetimpact/" + tbb
	testbench.CopyFiles("/packetimpact", "/test/packetimpact/tests/"+tbb)

	// Run tcpdump in the test bench unbuffered, without DNS resolution, just on
	// the interface with the test packets.
	snifferArgs := []string{
		"tcpdump", "-S", "-vvv", "-U", "-n", "-i", testNetDev,
	}
	snifferRegex := "tcpdump: listening.*\n"
	if *tshark {
		// Run tshark in the test bench unbuffered, without DNS resolution, just on
		// the interface with the test packets.
		snifferArgs = []string{
			"tshark", "-V", "-l", "-n", "-i", testNetDev,
			"-o", "tcp.check_checksum:TRUE",
			"-o", "udp.check_checksum:TRUE",
		}
		snifferRegex = "Capturing on.*\n"
	}

	if err := testbench.Create(runOpts, snifferArgs...); err != nil {
		t.Fatalf("unable to create container %s: %s", testbench.Name, err)
	}
	defer testbench.CleanUp()

	// Add ctrlNet as eth1 and testNet as eth2.
	if err := addNetworks(testbench, testbenchAddr, []*dockerutil.DockerNetwork{ctrlNet, testNet}); err != nil {
		t.Fatal(err)
	}

	if err := testbench.Start(); err != nil {
		t.Fatalf("unable to start container %s: %s", testbench.Name, err)
	}

	// Kill so that it will flush output.
	defer testbench.Exec(dockerutil.RunOpts{}, "killall", snifferArgs[0])

	if _, err := testbench.WaitForOutput(snifferRegex, 60*time.Second); err != nil {
		t.Fatalf("sniffer on %s never listened: %s", dut.Name, err)
	}

	// Because the Linux kernel receives the SYN-ACK but didn't send the SYN it
	// will issue a RST. To prevent this IPtables can be used to filter out all
	// incoming packets. The raw socket that packetimpact tests use will still see
	// everything.
	if _, err := testbench.Exec(dockerutil.RunOpts{}, "iptables", "-A", "INPUT", "-i", testNetDev, "-j", "DROP"); err != nil {
		t.Fatalf("unable to Exec iptables on container %s: %s", testbench.Name, err)
	}

	// FIXME(b/156449515): Some piece of the system has a race. The old
	// bash script version had a sleep, so we have one too. The race should
	// be fixed and this sleep removed.
	time.Sleep(time.Second)

	// Start a packetimpact test on the test bench. The packetimpact test sends
	// and receives packets and also sends POSIX socket commands to the
	// posix_server to be executed on the DUT.
	testArgs := []string{containerTestbenchBinary}
	testArgs = append(testArgs, extraTestArgs...)
	testArgs = append(testArgs,
		"--posix_server_ip", addressInSubnet(dutAddr, *ctrlNet.Subnet).String(),
		"--posix_server_port", ctrlPort,
		"--remote_ipv4", addressInSubnet(dutAddr, *testNet.Subnet).String(),
		"--local_ipv4", addressInSubnet(testbenchAddr, *testNet.Subnet).String(),
		"--remote_ipv6", remoteIPv6.String(),
		"--remote_mac", remoteMAC.String(),
		"--device", testNetDev,
	)
	_, err = testbench.Exec(dockerutil.RunOpts{}, testArgs...)
	if !*expectFailure && err != nil {
		t.Fatal("test failed:", err)
	}
	if *expectFailure && err == nil {
		t.Fatal("test failure expected but the test succeeded, enable the test and mark the corresponding bug as fixed")
	}
}

func addNetworks(d *dockerutil.Docker, addr net.IP, networks []*dockerutil.DockerNetwork) error {
	for _, dn := range networks {
		ip := addressInSubnet(addr, *dn.Subnet)
		// Connect to the network with the specified IP address.
		if err := dn.Connect(d, "--ip", ip.String()); err != nil {
			return fmt.Errorf("unable to connect container %s to network %s: %w", d.Name, dn.Name, err)
		}
	}
	return nil
}

// addressInSubnet combines the subnet provided with the address and returns a
// new address. The return address bits come from the subnet where the mask is 1
// and from the ip address where the mask is 0.
func addressInSubnet(addr net.IP, subnet net.IPNet) net.IP {
	var octets []byte
	for i := 0; i < 4; i++ {
		octets = append(octets, (subnet.IP.To4()[i]&subnet.Mask[i])+(addr.To4()[i]&(^subnet.Mask[i])))
	}
	return net.IP(octets)
}

// makeDockerNetwork makes a randomly-named network that will start with the
// namePrefix. The network will be a random /24 subnet.
func createDockerNetwork(n *dockerutil.DockerNetwork) error {
	randSource := rand.NewSource(time.Now().UnixNano())
	r1 := rand.New(randSource)
	// Class C, 192.0.0.0 to 223.255.255.255, transitionally has mask 24.
	ip := net.IPv4(byte(r1.Intn(224-192)+192), byte(r1.Intn(256)), byte(r1.Intn(256)), 0)
	n.Subnet = &net.IPNet{
		IP:   ip,
		Mask: ip.DefaultMask(),
	}
	return n.Create()
}

// deviceByIP finds a deviceInfo and device name from an IP address.
func deviceByIP(d *dockerutil.Docker, ip net.IP) (string, netdevs.DeviceInfo, error) {
	out, err := d.Exec(dockerutil.RunOpts{}, "ip", "addr", "show")
	if err != nil {
		return "", netdevs.DeviceInfo{}, fmt.Errorf("listing devices on %s container: %w", d.Name, err)
	}
	devs, err := netdevs.ParseDevices(out)
	if err != nil {
		return "", netdevs.DeviceInfo{}, fmt.Errorf("parsing devices from %s container: %w", d.Name, err)
	}
	testDevice, deviceInfo, err := netdevs.FindDeviceByIP(ip, devs)
	if err != nil {
		return "", netdevs.DeviceInfo{}, fmt.Errorf("can't find deviceInfo for container %s: %w", d.Name, err)
	}
	return testDevice, deviceInfo, nil
}
