# Copyright 2019 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

build: content/.jekyll-cache
	@bazel run //runsc -- help syscalls -format json -filename $(PWD)/syscalls.json
	@docker build -t gvisor-website .
	@docker run -v $$PWD:/work -w /work gcr.io/cloud-builders/npm ci
	@$(MAKE) update
.PHONY: build

content/.jekyll-cache:
	@mkdir -p $@ && chmod a+rw $@

lint:
	@docker run -v $$PWD:/work -w /work gcr.io/cloud-builders/npm run lint-md
.PHONY: lint

update: lint
	@sudo mkdir -p _site && sudo chmod a+rw _site
	@find content -type f -exec chmod a+r {} \; && find content -type d -exec chmod a+rx {} \;
	@docker run -v $$PWD:/site -w /site gvisor-website
.PHONY: build

clean:
	@sudo rm -rf _site node_modules syscalls.json
.PHONY: clean

server:
	@go run gvisor.dev/website/cmd/gvisor-website
.PHONY: server

deploy: update
	@docker run --entrypoint=gcloud gvisor-website app deploy app.yaml
.PHONY: deploy
