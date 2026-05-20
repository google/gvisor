This directory contains the checkpoint gofer, which provides the ability to save
and restore checkpoint files stored in Google Cloud Storage (GCS). It is built
as a separate binary to avoid pulling net/http into the main runsc binary, which
causes netpoll to fail (in fsgofers) due to an inability to find /etc/hosts.
