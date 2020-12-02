# Build Agent

This is the image used by the build agent. It is built and bundled via a
separate packaging mechanism in order to provide local caching and to ensure
that there is better build provenance. Note that continuous integration system
will generally deploy new agents from the primary branch, and will only deploy
as instances are recycled. Updates to this image should be made carefully.
