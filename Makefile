VERSION := $(shell grep 'const Version =' main.go | sed -E 's/.*"([^"]+)".*/\1/')
IMAGE_NAME := obegron/goturbo

.PHONY: docker-push
docker-push:
	docker buildx build --platform linux/amd64,linux/arm64 --provenance=true --sbom=true -t $(IMAGE_NAME):$(VERSION) -t $(IMAGE_NAME):latest . --push

.PHONY: show-version
show-version:
	@echo $(VERSION)
