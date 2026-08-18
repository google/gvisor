# Checkescape Analyzer

Checkescape allows recursive escape analysis for hot paths.

## Installation and Usage

The analyzer is integrated into the gVisor `nogo` framework. It automatically
applies to all code in this repository.

For external usage and to iterate quickly, it may be used as part of `go vet` or it can run as a standalone tool.
You can install the tool separately via:

```sh
go install gvisor.dev/gvisor/tools/checkescape/cmd/checkescape@go
```

And run it via:

```sh
go vet -vettool=$(go env GOBIN)/checkescape ./...
# or directly
checkescape ./...
```