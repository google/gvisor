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

# Build the system call doc generator.
FROM gcr.io/cloud-builders/go as syscalls
WORKDIR /src
COPY go.mod go.sum /src/
COPY cmd/generate-syscall-docs /src/cmd/generate-syscall-docs
RUN CGO_ENABLED=0 go build -o /bin/generate-syscall-docs gvisor.dev/website/cmd/generate-syscall-docs

# Generate the static site.
FROM jekyll/jekyll as jekyll
USER root
WORKDIR /site
RUN gem install html-proofer:3.10.2 nokogiri:1.10.1
RUN gem install jekyll-autoprefixer webrick jekyll-inline-svg
COPY --from=syscalls /bin/generate-syscall-docs /bin/generate-syscall-docs
CMD ["sh", "-c", "cat syscalls.json | /bin/generate-syscall-docs -out content/docs/user_guide/compatibility/ && jekyll build -t -s content -d _site && cp -a static/* _site && (cd _site && /usr/gem/bin/htmlproofer --disable-external --check-html .)"]
