// Copyright 2020 The gVisor Authors.
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

package injector

import (
	"fmt"
	"io/ioutil"
)

var (
	caKey      []byte
	caCert     []byte
	serverKey  []byte
	serverCert []byte
)

func init() {
	var (
		caKeyErr      error
		caCertErr     error
		serverKeyErr  error
		serverCertErr error
	)
	caKey, caKeyErr = ioutil.ReadFile("caKey.pem")
	caCert, caCertErr = ioutil.ReadFile("caCert.pem")
	serverKey, serverKeyErr = ioutil.ReadFile("serverKey.pem")
	serverCert, serverCertErr = ioutil.ReadFile("serverCert.pem")
	for _, err := range []error{caKeyErr, caCertErr, serverKeyErr, serverCertErr} {
		if err != nil {
			panic(fmt.Errorf("unable to create certificates: %v", err))
		}
	}
}
