# Using CNI

This tutorial will show you how to set up networking for a gVisor sandbox using
the
[Container Networking Interface (CNI)](https://github.com/containernetworking/cni).

## Install CNI Plugins

First you will need to install the CNI plugins. CNI plugins are used to set up a
network namespace that `runsc` can use with the sandbox.

Start by creating the directories for CNI plugin binaries:

```
sudo mkdir -p /opt/cni/bin
```

Download the CNI plugins:

```
wget https://github.com/containernetworking/plugins/releases/download/v0.8.3/cni-plugins-linux-amd64-v0.8.3.tgz
```

Next, unpack the plugins into the CNI binary directory:

```
sudo tar -xvf cni-plugins-linux-amd64-v0.8.3.tgz -C /opt/cni/bin/
```

## Configure CNI Plugins

This section will show you how to configure CNI plugins. This tutorial will use
the "bridge" and "loopback" plugins which will create the necessary bridge and
loopback devices in our network namespace. However, you should be able to use
any CNI compatible plugin to set up networking for gVisor sandboxes.

The bridge plugin configuration specifies the IP address subnet range for IP
addresses that will be assigned to sandboxes as well as the network routing
configuration. This tutorial will assign IP addresses from the `10.22.0.0/16`
range and allow all outbound traffic, however you can modify this configuration
to suit your use case.

Create the bridge and loopback plugin configurations:

```
sudo mkdir -p /etc/cni/net.d

sudo sh -c 'cat > /etc/cni/net.d/10-bridge.conf << EOF
{
  "cniVersion": "0.3.1",
  "name": "mynet",
  "type": "bridge",
  "bridge": "cni0",
  "isGateway": true,
  "ipMasq": true,
  "ipam": {
    "type": "host-local",
    "subnet": "10.22.0.0/16",
    "routes": [
      { "dst": "0.0.0.0/0" }
    ]
  }
}
EOF'

sudo sh -c 'cat > /etc/cni/net.d/99-loopback.conf << EOF
{
  "cniVersion": "0.3.1",
  "name": "lo",
  "type": "loopback"
}
EOF'
```

## Create a Network Namespace

For each gVisor sandbox you will create a network namespace and configure it
using CNI. First, create a random network namespace name and then create the
namespace.

The network namespace path will then be `/var/run/netns/${CNI_CONTAINERID}`.

```
export CNI_PATH=/opt/cni/bin
export CNI_CONTAINERID=$(printf '%x%x%x%x' $RANDOM $RANDOM $RANDOM $RANDOM)
export CNI_COMMAND=ADD
export CNI_NETNS=/var/run/netns/${CNI_CONTAINERID}

sudo ip netns add ${CNI_CONTAINERID}
```

Next, run the bridge and loopback plugins to apply the configuration that was
created earlier to the namespace. Each plugin outputs some JSON indicating the
results of executing the plugin. For example, The bridge plugin's response
includes the IP address assigned to the ethernet device created in the network
namespace. Take note of the IP address for use later.

```
export CNI_IFNAME="eth0"
sudo -E /opt/cni/bin/bridge < /etc/cni/net.d/10-bridge.conf
export CNI_IFNAME="lo"
sudo -E /opt/cni/bin/loopback < /etc/cni/net.d/99-loopback.conf
```

Get the IP address assigned to our sandbox:

```
POD_IP=$(sudo ip netns exec ${CNI_CONTAINERID} ip -4 addr show eth0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
```

## Create the OCI Bundle

Now that our network namespace is created and configured, we can create the OCI
bundle for our container. As part of the bundle's `config.json` we will specify
that the container use the network namespace that we created.

The container will run a simple python webserver that we will be able to connect
to via the IP address assigned to it via the bridge CNI plugin.

Create the bundle and root filesystem directories:

```
sudo mkdir -p bundle
cd bundle
sudo mkdir rootfs
sudo docker export $(docker create python) | sudo tar --same-owner -pxf - -C rootfs
sudo mkdir -p rootfs/var/www/html
sudo sh -c 'echo "Hello World!" > rootfs/var/www/html/index.html'
```

Next create the `config.json` specifying the network namespace.

```
sudo runsc spec \
    --cwd /var/www/html \
    --netns /var/run/netns/${CNI_CONTAINERID} \
    -- python -m http.server
```

## Run the Container

Now we can run and connect to the webserver. Run the container in gVisor. Use
the same ID used for the network namespace to be consistent:

```
sudo runsc run -detach ${CNI_CONTAINERID}
```

Connect to the server via the sandbox's IP address:

```
curl http://${POD_IP}:8000/
```

You should see the server returning `Hello World!`.

## Cleanup

After you are finished running the container, you can clean up the network
namespace .

```
sudo runsc kill ${CNI_CONTAINERID}
sudo runsc delete ${CNI_CONTAINERID}

export CNI_COMMAND=DEL

export CNI_IFNAME="lo"
sudo -E /opt/cni/bin/loopback < /etc/cni/net.d/99-loopback.conf
export CNI_IFNAME="eth0"
sudo -E /opt/cni/bin/bridge < /etc/cni/net.d/10-bridge.conf

sudo ip netns delete ${CNI_CONTAINERID}
```
