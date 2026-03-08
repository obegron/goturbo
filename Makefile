VERSION := $(shell grep 'const Version =' main.go | sed -E 's/.*"([^"]+)".*/\1/')
IMAGE_NAME := obegron/goturbo

.PHONY: build
build:
	CGO_ENABLED=0 go build -ldflags="-s -w" -o goturbo .

.PHONY: run
run:
	go run .

.PHONY: docker-build
docker-build:
	docker buildx build --platform linux/amd64,linux/arm64 -t $(IMAGE_NAME):$(VERSION) -t $(IMAGE_NAME):latest .

.PHONY: docker-push
docker-push:
	docker buildx build --platform linux/amd64,linux/arm64 --provenance=true --sbom=true -t $(IMAGE_NAME):$(VERSION) -t $(IMAGE_NAME):latest . --push

.PHONY: docker-rebuild-tag
docker-rebuild-tag:
	@if [ -z "$(TAG)" ]; then echo "Error: TAG is not set. Use 'make docker-rebuild-tag TAG=vX.Y.Z'"; exit 1; fi
	git checkout $(TAG)
	docker buildx build --platform linux/amd64,linux/arm64 -t $(IMAGE_NAME):$(TAG) .
	git checkout -

.PHONY: docker-push-tag
docker-push-tag:
	@if [ -z "$(TAG)" ]; then echo "Error: TAG is not set. Use 'make docker-push-tag TAG=vX.Y.Z'"; exit 1; fi
	git checkout $(TAG)
	docker buildx build --platform linux/amd64,linux/arm64 --provenance=true --sbom=true -t $(IMAGE_NAME):$(TAG) . --push
	git checkout -

.PHONY: show-version
show-version:
	@echo $(VERSION)

.PHONY: clean
clean:
	rm -f goturbo goturbo-*

.PHONY: help
help:
	@echo "goTurbo build targets:"
	@echo "  make build        - Build local binary (stripped)"
	@echo "  make run          - Run locally"
	@echo "  make smoke-maven-k3d - Run Maven HTTP smoke test in a fresh k3d cluster"
	@echo "  make docker-build - Build multi-arch Docker image"
	@echo "  make docker-push  - Build and push to registry"
	@echo "  make docker-rebuild-tag TAG=vX.Y.Z - Rebuild specific tag"
	@echo "  make docker-push-tag TAG=vX.Y.Z    - Rebuild and push specific tag to registry"
	@echo "  make show-version - Show current version"
	@echo "  make clean        - Remove built binaries"

.PHONY: smoke-maven-k3d
smoke-maven-k3d:
	./integration/maven-webdav-smoke/run-k3d.sh
