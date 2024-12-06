FROM ubuntu:24.04

# The iptables package installs both iptables-legacy and iptables-nft, with
# iptables symlinked to the latter.
RUN apt update && apt install -y iptables
