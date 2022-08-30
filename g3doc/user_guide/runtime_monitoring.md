# Runtime Monitoring

The runtime monitoring feature provides an interface to observe runtime behavior
of applications running inside gVisor. Although it can be used for many
purposes, it was built with the primary focus on threat detection. Out of the
box, gVisor comes with support to stream application actions (called trace
points) to an external process, that is used to validate the actions and alert
when abnormal behavior is detected. Trace points are available for all syscalls
and other important events in the system, e.g. container start. More trace
points can be easily added as needed. The trace points are sent to a process
running alongside the sandbox, which is isolated from the sandbox for security
reasons. Additionally, the monitoring process can be shared by many sandboxes.

You can use the following links to learn more:

*   [Overview](https://github.com/google/gvisor/blob/master/pkg/sentry/seccheck/README.md)
*   [How to implement a monitoring process](https://github.com/google/gvisor/blob/master/pkg/sentry/seccheck/sinks/remote/README.md)
*   [Design document](https://docs.google.com/document/d/1RQQKzeFpO-zOoBHZLA-tr5Ed_bvAOLDqgGgKhqUff2A)
*   [Configuring Falco with gVisor](https://gvisor.dev/docs/tutorials/falco/)
*   [Tracereplay tool for testing](https://github.com/google/gvisor/blob/master/tools/tracereplay/README.md)
