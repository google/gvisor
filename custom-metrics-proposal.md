# Custom Path-Specific Metrics for GVisor

## Motivation

Current GVisor metrics provide general filesystem and network access information, but lack path-specific granularity that is crucial for understanding application behavior. Many use cases require tracking access patterns to specific directories or file systems to optimize performance, ensure security compliance, and enable better observability.

For example, organizations need to:
- Monitor access patterns to sensitive directories
- Track filesystem usage by application components  
- Understand data flow patterns for optimization
- Enable fine-grained debugging of filesystem bottlenecks

The existing GVisor metrics system provides excellent general visibility but cannot answer questions like "how often are specific paths being accessed?" or "which applications are reading/writing to particular directories?" This gap limits the effectiveness of performance analysis and security monitoring.

## Proposed Solutions

We propose two approaches to extend GVisor's metrics system with path-specific tracking capabilities:

### Solution 1: Full Syscall Configuration (Recommended)

**Overview**: Implement a new `--path-metrics-config` flag that accepts a YAML configuration file specifying both path prefixes to monitor AND which specific syscalls to track for each path.

**Implementation**: 
- Add command-line flag for runtime configuration
- YAML config format for specifying monitored paths and specific syscalls
- Filesystem layer modifications to intercept and track configured syscalls
- Emit separate metrics counters for each path-syscall combination

**Usage**:
```bash
# Runtime integration
runsc create --path-metrics-config=/etc/gvisor/path-metrics.yaml container_id

# Docker integration  
docker run --runtime=runsc \
  --runtime-arg="--path-metrics-config=/etc/gvisor/path-metrics.yaml" \
  --name=container image
```

**Configuration Example**:
```yaml
path_metrics:
  - path_prefix: "/mnt/data"
    syscalls: ["open", "openat", "read", "write", "pread", "pwrite", "stat", "fstat", "close"]
  - path_prefix: "/app/storage"  
    syscalls: ["open", "read", "write", "stat"]
  - path_prefix: "/tmp"
    syscalls: ["open", "write", "close"]
```

**Usage**:
```bash
# Export all metrics including path-specific ones
sudo runsc --root=/var/run/docker/runtime-runc/moby export-metrics container_id | grep "runsc_path_"
```

**Expected Output**:
```
# HELP runsc_path_syscall_opens Number of open syscalls for specific path.
# TYPE runsc_path_syscall_opens counter
runsc_path_syscall_opens{sandbox="c7ce77796e0ece4c",path="/mnt/data"} 142 1674690410469
runsc_path_syscall_opens{sandbox="c7ce77796e0ece4c",path="/app/storage"} 67 1674690410469

# HELP runsc_path_syscall_reads Number of read syscalls for specific path.
# TYPE runsc_path_syscall_reads counter
runsc_path_syscall_reads{sandbox="c7ce77796e0ece4c",path="/mnt/data"} 1057 1674690410469
runsc_path_syscall_reads{sandbox="c7ce77796e0ece4c",path="/app/storage"} 234 1674690410469

# HELP runsc_path_syscall_writes Number of write syscalls for specific path.
# TYPE runsc_path_syscall_writes counter
runsc_path_syscall_writes{sandbox="c7ce77796e0ece4c",path="/mnt/data"} 89 1674690410469
```

**Benefits**:
- Maximum flexibility for different monitoring needs
- Can track any syscall pattern for specific paths
- Extensible to new paths and syscall combinations
- Upstream acceptance potential due to comprehensive utility
- Fine-grained control over performance impact

**Trade-offs**:
- More complex configuration management
- Higher implementation complexity
- Requires deeper syscall interception

### Solution 2: Simplified Path-Only Configuration

**Overview**: Implement a streamlined configuration approach that only requires specifying path prefixes, automatically tracking the most commonly needed metrics (read and write operations) for those paths.

**Implementation**:
- Same `--path-metrics-config` flag but simplified config format
- Automatically tracks read/write operations and byte counts
- Focus on the most popular use case (file access patterns)
- Simpler filesystem layer modifications

**Configuration Example**:
```yaml
monitored_paths:
  - "/mnt/data"
  - "/app/storage" 
  - "/tmp"
```

**Usage**:
```bash
# Export path-specific read/write metrics
sudo runsc --root=/var/run/docker/runtime-runc/moby export-metrics container_id | grep "runsc_path_"
```

**Expected Output**:
```
# HELP runsc_path_read_operations Number of read operations for specific path.
# TYPE runsc_path_read_operations counter
runsc_path_read_operations{sandbox="c7ce77796e0ece4c",path="/mnt/data"} 1057 1674690410469
runsc_path_read_operations{sandbox="c7ce77796e0ece4c",path="/app/storage"} 234 1674690410469

# HELP runsc_path_write_operations Number of write operations for specific path.
# TYPE runsc_path_write_operations counter  
runsc_path_write_operations{sandbox="c7ce77796e0ece4c",path="/mnt/data"} 89 1674690410469

# HELP runsc_path_bytes_read Total bytes read from specific path.
# TYPE runsc_path_bytes_read counter
runsc_path_bytes_read{sandbox="c7ce77796e0ece4c",path="/mnt/data"} 2847392 1674690410469
runsc_path_bytes_read{sandbox="c7ce77796e0ece4c",path="/app/storage"} 1024768 1674690410469

# HELP runsc_path_bytes_written Total bytes written to specific path.
# TYPE runsc_path_bytes_written counter
runsc_path_bytes_written{sandbox="c7ce77796e0ece4c",path="/mnt/data"} 156432 1674690410469
```

**Benefits**:
- Simple configuration - just specify paths
- Covers most common monitoring needs (read/write patterns)
- Easier to deploy and maintain
- Lower implementation complexity
- Still configurable and flexible for path selection

**Trade-offs**:
- Less granular than full syscall tracking
- Fixed to read/write metrics only
- Cannot track other syscalls like stat, open patterns


## Next Steps

Both solutions use the same flag mechanism and can be implemented incrementally. We'd appreciate feedback on:

1. Which approach better aligns with GVisor's design philosophy
2. Any concerns about the proposed configuration formats  
3. Preferred implementation approach for the filesystem layer modifications
4. Feedback on the proposed metric naming conventions and output format
5. Interest in upstream contribution and collaboration