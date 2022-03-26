module gvisor.dev/gvisor

go 1.17

require (
	github.com/BurntSushi/toml v0.3.1
	github.com/bazelbuild/rules_go v0.30.0
	github.com/bits-and-blooms/bitset v1.2.0
	github.com/cenkalti/backoff v1.1.1-0.20190506075156-2146c9339422
	github.com/containerd/cgroups v1.0.1
	github.com/containerd/console v1.0.1
	github.com/containerd/containerd v1.3.9
	github.com/containerd/fifo v1.0.0
	github.com/containerd/go-runc v1.0.0
	github.com/containerd/typeurl v1.0.2
	github.com/coreos/go-systemd/v22 v22.3.2
	github.com/gofrs/flock v0.8.0
	github.com/gogo/protobuf v1.3.2
	github.com/google/btree v1.0.1
	github.com/google/subcommands v1.0.2-0.20190508160503-636abe8753b8
	github.com/kr/pty v1.1.4-0.20190131011033-7dc38fb350b1
	github.com/mattbaird/jsonpatch v0.0.0-20171005235357-81af80346b1a
	github.com/mohae/deepcopy v0.0.0-20170308212314-bb9b5e7adda9
	github.com/opencontainers/runtime-spec v1.0.3-0.20211123151946-c2389c3cb60a
	github.com/sirupsen/logrus v1.8.1
	github.com/syndtr/gocapability v0.0.0-20180916011248-d98352740cb2
	github.com/vishvananda/netlink v1.0.1-0.20190930145447-2ec5bdc52b86
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	golang.org/x/sys v0.0.0-20211019181941-9d821ace8654
	golang.org/x/time v0.0.0-20191024005414-555d28b269f0
	google.golang.org/grpc v1.42.0-dev.0.20211020220737-f00baa6c3c84
	google.golang.org/protobuf v1.27.1
	k8s.io/api v0.16.13
	k8s.io/apimachinery v0.16.14-rc.0
	k8s.io/client-go v0.16.13
)

require (
	cloud.google.com/go/bigquery v1.8.0
	github.com/Microsoft/go-winio v0.5.1 // indirect
	github.com/Microsoft/hcsshim v0.8.14 // indirect
	github.com/containerd/continuity v0.2.1 // indirect
	github.com/containerd/ttrpc v1.0.2 // indirect
	github.com/coreos/go-systemd/v22 v22.1.0
	github.com/docker/distribution v2.8.1+incompatible // indirect
	github.com/docker/docker v20.10.13+incompatible
	github.com/docker/go-connections v0.4.0
	github.com/godbus/dbus/v5 v5.0.3
	github.com/golang/mock v1.4.4
	github.com/google/go-cmp v0.5.6
	github.com/google/go-github v17.0.0+incompatible
	github.com/google/go-querystring v1.1.0 // indirect
	github.com/google/gopacket v1.1.19
	github.com/google/pprof v0.0.0-20200708004538-1a94d8640e99
	github.com/google/uuid v1.1.2
	github.com/googleapis/gnostic v0.4.0 // indirect
	github.com/gorilla/mux v1.8.0 // indirect
	github.com/hashicorp/go-multierror v1.1.0 // indirect
	github.com/moby/term v0.0.0-20210619224110-3f7ff695adc6 // indirect
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.0.2 // indirect
	github.com/opencontainers/runc v1.0.0-rc90 // indirect
	github.com/vishvananda/netns v0.0.0-20211101163701-50045581ed74 // indirect
	github.com/xeipuuv/gojsonschema v1.2.0
	go.opencensus.io v0.23.0 // indirect
	go.uber.org/multierr v1.1.0
	golang.org/x/net v0.0.0-20211015210444-4f30a5c0130f
	golang.org/x/oauth2 v0.0.0-20211005180243-6b3c2da341f1
	golang.org/x/tools v0.1.9
	google.golang.org/api v0.30.0
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/genproto v0.0.0-20210722135532-667f2b7c528f // indirect
	gopkg.in/yaml.v2 v2.2.8
	gotest.tools/v3 v3.1.0 // indirect
	honnef.co/go/tools v0.0.1-2020.1.4
)
