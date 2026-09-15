# A Debian container that boots systemd and runs a headless Wayland GNOME
# session, accessible over RDP from port 3389.
#
#   docker build -t systemd-debian-gnome - < Dockerfile.standalone
#   docker run -d --name gnome --privileged \ -p 127.0.0.1:3389:3389 \
#     systemd-debian-gnome
#   xfreerdp3 /v:localhost:3389 /u:gnome /p:gnome /cert:ignore /sound

FROM scratch AS vscode-deb
ADD https://go.microsoft.com/fwlink/?LinkID=760868 /code.deb

FROM debian:trixie
ENV container=docker

RUN <<'EOF'
set -eux
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y \
    systemd systemd-sysv dbus-user-session sudo \
    gnome-core gnome-remote-desktop gnome-terminal \
    libgl1-mesa-dri pipewire-audio wireplumber openssl
apt-get clean
rm -rf /var/lib/apt/lists/*
EOF

ADD --chmod=0644 https://dl.google.com/linux/linux_signing_key.pub \
    /etc/apt/keyrings/google-chrome.asc

RUN <<'EOF'
set -eux
export DEBIAN_FRONTEND=noninteractive
cat > /etc/apt/sources.list.d/google-chrome.sources <<'INNER'
Types: deb
URIs: https://dl.google.com/linux/chrome/deb/
Suites: stable
Components: main
Architectures: amd64
Signed-By: /etc/apt/keyrings/google-chrome.asc
INNER

apt-get update
apt-get install -y google-chrome-stable
apt-get purge -y firefox-esr
apt-get autoremove --purge -y
apt-get clean
rm -rf /var/lib/apt/lists/*
EOF

RUN --mount=from=vscode-deb,target=/mnt/vscode <<'EOF'
set -eux
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y /mnt/vscode/code.deb
apt-get clean
rm -rf /var/lib/apt/lists/*
EOF

RUN <<'EOF'
set -eu
mask() { ln -sf /dev/null "/etc/systemd/system/$1"; }
mask gdm3.service
mask display-manager.service
mask dbus-org.freedesktop.ModemManager1.service
mask fwupd.service
mask systemd-networkd.service
mask systemd-networkd.socket
mask systemd-resolved.service
EOF

# Disable wireplumber libcamera
RUN <<'EOF'
set -eu
mkdir -p /etc/wireplumber/wireplumber.conf.d
cat > /etc/wireplumber/wireplumber.conf.d/50-no-libcamera.conf <<'INNER'
wireplumber.profiles = {
  main = {
    monitor.libcamera = disabled
    monitor.libcamera.reserve-device = disabled
  }
}
INNER
EOF

RUN <<'EOF'
set -eu
mkdir -p /etc/environment.d
cat > /etc/environment.d/90-gnome-headless.conf <<'INNER'
XDG_SESSION_TYPE=wayland
XDG_CURRENT_DESKTOP=GNOME
GNOME_SHELL_SESSION_MODE=gnome
LIBGL_ALWAYS_SOFTWARE=1
INNER

mkdir -p /etc/systemd/user/org.gnome.Shell@wayland.service.d
cat > /etc/systemd/user/org.gnome.Shell@wayland.service.d/headless.conf <<'INNER'
[Service]
ExecStart=
ExecStart=/usr/bin/gnome-shell --wayland --headless
INNER

cat > /etc/systemd/user/gnome-headless-session.service <<'INNER'
[Unit]
Description=Headless GNOME session
After=dbus.socket
[Service]
Type=simple
ExecStart=/usr/bin/gnome-session --session=gnome
Restart=no
[Install]
WantedBy=default.target
INNER

mkdir -p /etc/systemd/user/default.target.wants /etc/systemd/user/gnome-session.target.wants
ln -sf /etc/systemd/user/gnome-headless-session.service \
    /etc/systemd/user/default.target.wants/gnome-headless-session.service
ln -sf /usr/lib/systemd/user/gnome-remote-desktop-headless.service \
    /etc/systemd/user/gnome-session.target.wants/gnome-remote-desktop-headless.service
EOF

RUN <<'EOF'
set -eu
cat > /usr/share/glib-2.0/schemas/90_gnome-headless-rdp.gschema.override <<'INNER'
[org.gnome.shell]
favorite-apps=['google-chrome.desktop', 'org.gnome.Nautilus.desktop', 'org.gnome.Software.desktop', 'org.gnome.TextEditor.desktop', 'org.gnome.Calculator.desktop', 'yelp.desktop']

[org.gnome.desktop.remote-desktop.rdp]
enable=true
view-only=false
negotiate-port=false
tls-cert='/etc/gnome-remote-desktop/rdp-tls.crt'
tls-key='/etc/gnome-remote-desktop/rdp-tls.key'

[org.gnome.desktop.session]
idle-delay=0

[org.gnome.desktop.screensaver]
idle-activation-enabled=false
lock-enabled=false

[org.gnome.settings-daemon.plugins.power]
sleep-inactive-ac-type='nothing'
sleep-inactive-battery-type='nothing'
idle-dim=false
INNER
glib-compile-schemas /usr/share/glib-2.0/schemas
EOF

ARG RDP_USER=gnome
ARG RDP_PASSWORD=gnome

RUN <<EOF
set -eu
useradd -m -s /bin/bash -G sudo "$RDP_USER"
echo "$RDP_USER:$RDP_PASSWORD" | chpasswd
mkdir -p /var/lib/systemd/linger
touch "/var/lib/systemd/linger/$RDP_USER"
EOF

RUN <<EOF
set -eu
mkdir -p /etc/gnome-remote-desktop
openssl req -new -newkey rsa:4096 -days 3650 -nodes -x509 \
    -subj "/C=US/ST=NA/L=NA/O=incus2oci/CN=gnome-headless" \
    -out /etc/gnome-remote-desktop/rdp-tls.crt \
    -keyout /etc/gnome-remote-desktop/rdp-tls.key 2>/dev/null
chgrp "$RDP_USER" /etc/gnome-remote-desktop/rdp-tls.key
chmod 640 /etc/gnome-remote-desktop/rdp-tls.key

HOME_DIR="$(getent passwd "$RDP_USER" | cut -d: -f6)"
mkdir -p "$HOME_DIR/.local/share/gnome-remote-desktop"
cat > "$HOME_DIR/.local/share/gnome-remote-desktop/credentials.ini" <<INNER
[RDP]
credentials={'username': <'$RDP_USER'>, 'password': <'$RDP_PASSWORD'>}
INNER
chmod 600 "$HOME_DIR/.local/share/gnome-remote-desktop/credentials.ini"
chown -R "$RDP_USER:$RDP_USER" "$HOME_DIR/.local"
EOF

RUN <<'EOF'
set -eu
cat > /usr/local/sbin/oci-init <<'INNER'
#!/bin/sh
if [ ! -w /sys/fs/cgroup ]; then
	mount -o remount,rw /sys/fs/cgroup 2>/dev/null \
		|| echo "oci-init: warning: /sys/fs/cgroup is read-only and could not be" \
		        "remounted; systemd will fail to start. Needs CAP_SYS_ADMIN, and" \
		        "AppArmor's docker-default profile must not be blocking mount()." >&2
fi
exec "$@"
INNER
chmod +x /usr/local/sbin/oci-init
EOF

EXPOSE 3389

STOPSIGNAL SIGRTMIN+3

ENTRYPOINT ["/usr/local/sbin/oci-init"]
CMD ["/sbin/init"]
