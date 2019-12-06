HUGO_VERSION := 0.53
HTMLPROOFER_VERSION := 3.10.2
GCLOUD := gcloud
GCP_PROJECT := gvisor-website

# Source Go files, example: main.go, foo/bar.go.
GEN_SOURCE = $(wildcard cmd/generate-syscall-docs/*)
APP_SOURCE = $(wildcard cmd/gvisor-website/*)
# Target Go files, example: public/main.go, public/foo/bar.go.
APP_TARGET = $(patsubst cmd/gvisor-website/%,public/%,$(APP_SOURCE))

default: website
.PHONY: default

website: all-upstream app static-production
.PHONY: website

app: $(APP_TARGET)
.PHONY: app

public:
	mkdir -p public

# Load repositories.
upstream:
	mkdir -p upstream
upstream-%: upstream
	if [ -d upstream/$* ]; then (cd upstream/$* && git pull --rebase); else git clone https://gvisor.googlesource.com/$*/ upstream/$*; fi
all-upstream: upstream-gvisor upstream-community
# All repositories are listed here: force updates.
.PHONY: all-upstream upstream-%

# This target regenerates the sigs directory; this is not PHONY.
content/docs/community/sigs: upstream/community $(wildcard upstream/community/sigs/*)
	rm -rf content/docs/community/sigs && mkdir -p content/docs/community/sigs
	for file in $(shell cd upstream/community/sigs && ls -1 *.md | cut -d'.' -f1 | grep -v TEMPLATE); do      \
		title=$$(cat upstream/community/sigs/$$file.md | grep -E '^# ' | cut -d' ' -f2-);                 \
		echo -e "+++\ntitle = \"$$title\"\n+++\n" > content/docs/community/sigs/$$file.md;                  \
		cat upstream/community/sigs/$$file.md |grep -v -E '^# ' >> content/docs/community/sigs/$$file.md; \
	done

$(APP_TARGET): public $(APP_SOURCE)
	cp -a cmd/gvisor-website/$(patsubst public/%,%,$@) public/

static-production: hugo-docker-image compatibility-docs node_modules config.toml $(shell find archetypes assets content themes -type f | sed 's/ /\\ /g')
	docker run \
	  --rm \
	  -e HUGO_ENV="production" \
	  -e USER="$(shell id -u)" \
	  -e HOME="/tmp" \
	  -u="$(shell id -u):$(shell id -g)" \
	  -v $(PWD):/workspace \
	  -w /workspace \
	  gcr.io/gvisor-website/hugo:$(HUGO_VERSION) \
	  hugo
.PHONY: static-production

static-staging: hugo-docker-image compatibility-docs node_modules config.toml $(shell find archetypes assets content themes -type f | sed 's/ /\\ /g')                           
	docker run \
	  --rm \
	  -e HUGO_ENV="production" \
	  -e USER="$(shell id -u)" \
	  -e HOME="/tmp" \
	  -u="$(shell id -u):$(shell id -g)" \
	  -v $(PWD):/workspace \
	  -w /workspace \
	  gcr.io/gvisor-website/hugo:$(HUGO_VERSION) \
	  hugo \
	    -b "https://staging-$(shell git branch | grep \* | cut -d ' ' -f2)-dot-gvisor-website.appspot.com"
.PHONY: static-staging

node_modules: package.json package-lock.json
	# Use npm ci because npm install will update the package-lock.json.
	# See: https://github.com/npm/npm/issues/18286
	docker run \
	  --rm \
	  -e USER="$(shell id -u)" \
	  -e HOME="/tmp" \
	  -u="$(shell id -u):$(shell id -g)" \
	  -v $(PWD):/workspace \
	  -w /workspace \
	  --entrypoint 'npm' \
	  node ci

upstream/gvisor/bazel-bin/runsc/linux_amd64_pure_stripped/runsc: upstream-gvisor
	mkdir -p /tmp/gvisor-website/build_output
	docker run \
	  --rm \
	  -v $(PWD)/upstream/gvisor:/workspace \
	  -v /tmp/gvisor-website/build_output:/tmp/gvisor-website/build_output \
	  -w /workspace \
	  --entrypoint 'sh' \
	  l.gcr.io/google/bazel \
	  -c '\
		groupadd --gid $(shell id -g) $(shell id -gn) && \
		useradd --uid $(shell id -u) --gid $(shell id -g) -ms /bin/bash $(USER) && \
		su $(USER) -c "bazel --output_user_root=/tmp/gvisor-website/build_output build //runsc"'

bin/generate-syscall-docs: $(GEN_SOURCE)
	mkdir -p bin/
	go build -o bin/generate-syscall-docs gvisor.dev/website/cmd/generate-syscall-docs

compatibility-docs: bin/generate-syscall-docs upstream/gvisor/bazel-bin/runsc/linux_amd64_pure_stripped/runsc
	./upstream/gvisor/bazel-bin/runsc/linux_amd64_pure_stripped/runsc help syscalls -o json | ./bin/generate-syscall-docs -out ./content/docs/user_guide/compatibility/
.PHONY: compatibility-docs

check: htmlproofer-docker-image website
	docker run -v $(shell pwd)/public:/public gcr.io/gvisor-website/html-proofer:$(HTMLPROOFER_VERSION) htmlproofer --disable-external --check-html public/static
.PHONY: check

# Run a local content development server. Redirects will not be supported.
devserver: hugo-docker-image all-upstream compatibility-docs
	docker run \
	  --rm \
	  -e USER="$(shell id -u)" \
	  -e HOME="/tmp" \
	  -u="$(shell id -u):$(shell id -g)" \
	  -v $(PWD):/workspace \
	  -w /workspace \
	  -p 8080:8080 \
	  gcr.io/gvisor-website/hugo:$(HUGO_VERSION) \
	  hugo server \
		-FD \
		--bind 0.0.0.0 \
		--port 8080
.PHONY: server

server: website
	cd public/ && go run main.go --custom-domain localhost
.PHONY: server

# Stage the website to App Engine at a version based on the git branch name.
stage: all-upstream app static-staging
	# Disallow indexing staged content.
	printf "User-agent: *\nDisallow: /" > public/static/robots.txt
	cd public && $(GCLOUD) app deploy -v staging-$(shell git branch | grep \* | cut -d ' ' -f2) --no-promote
.PHONY: stage

# CI related Commmands
##############################################################################

# Submit a build to Cloud Build manually. Used to test cloudbuild.yaml changes.
cloud-build:
	gcloud builds submit --config cloudbuild.yaml .

# Build the hugo Docker image.
hugo-docker-image:
	docker build --build-arg HUGO_VERSION=$(HUGO_VERSION) -t gcr.io/gvisor-website/hugo:$(HUGO_VERSION) cloudbuild/hugo/
.PHONY: hugo-docker-image

# Build the html-proofer image used by Cloud Build.
htmlproofer-docker-image:
	docker build --build-arg HTMLPROOFER_VERSION=$(HTMLPROOFER_VERSION) -t gcr.io/gvisor-website/html-proofer:$(HTMLPROOFER_VERSION) cloudbuild/html-proofer/
.PHONY: htmlproofer-docker-image

clean:
	rm -rf public/ resources/ node_modules/ upstream/ content/docs/user_guide/compatibility/linux/
.PHONY: clean
