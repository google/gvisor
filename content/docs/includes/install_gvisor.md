> Note: gVisor supports only x86\_64 and requires Linux 3.17+.

The easiest way to get `runsc` is from the [latest nightly
build][latest-nightly]. After you download the binary, check it against the
SHA512 [checksum file][latest-hash].

Older builds can also be found here:
`https://storage.googleapis.com/gvisor/releases/nightly/${yyyy-mm-dd}/runsc`

With corresponding SHA512 checksums here:
`https://storage.googleapis.com/gvisor/releases/nightly/${yyyy-mm-dd}/runsc.sha512`

**It is important to copy this binary to a location that is accessible to all
users, and make sure it is executable to all users**, since `runsc` executes itself
as user `nobody` to avoid unnecessary privileges. The `/usr/local/bin` directory is
a good place to put the `runsc` binary.

```bash
wget https://storage.googleapis.com/gvisor/releases/nightly/latest/runsc
wget https://storage.googleapis.com/gvisor/releases/nightly/latest/runsc.sha512
sha512sum -c runsc.sha512
chmod a+x runsc
sudo mv runsc /usr/local/bin
```

[latest-nightly]: https://storage.googleapis.com/gvisor/releases/nightly/latest/runsc
[latest-hash]: https://storage.googleapis.com/gvisor/releases/nightly/latest/runsc.sha512
[oci]: https://www.opencontainers.org
