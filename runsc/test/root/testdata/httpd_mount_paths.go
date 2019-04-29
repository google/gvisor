// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package testdata

// HttpdMountPaths is a JSON config for an httpd container with additional
// mounts.
const HttpdMountPaths = `
{
  "metadata": {
    "name": "httpd"
  },
  "image":{
    "image": "httpd"
  },
  "mounts": [
      {
        "container_path": "/var/run/secrets/kubernetes.io/serviceaccount",
        "host_path": "/var/lib/kubelet/pods/82bae206-cdf5-11e8-b245-8cdcd43ac064/volumes/kubernetes.io~secret/default-token-2rpfx",
        "readonly": true
      },
      {
        "container_path": "/etc/hosts",
        "host_path": "/var/lib/kubelet/pods/82bae206-cdf5-11e8-b245-8cdcd43ac064/etc-hosts",
        "readonly": false
      },
      {
        "container_path": "/dev/termination-log",
        "host_path": "/var/lib/kubelet/pods/82bae206-cdf5-11e8-b245-8cdcd43ac064/containers/httpd/d1709580",
        "readonly": false
      },
      {
        "container_path": "/usr/local/apache2/htdocs/test",
        "host_path": "/var/lib/kubelet/pods/82bae206-cdf5-11e8-b245-8cdcd43ac064",
        "readonly": true
      }
  ],
  "linux": {
  },
  "log_path": "httpd.log"
}
`
