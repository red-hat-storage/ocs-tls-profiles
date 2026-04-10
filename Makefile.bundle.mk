# defining variables here before including "Makefile" makes these variables unique for current makefile
IMAGE_REGISTRY ?= quay.io
REGISTRY_NAMESPACE ?= ocs-dev
IMAGE_TAG ?= latest
IMAGE_NAME ?= ocs-tls-profiles
VERSION ?= 4.22.0

include Makefile

BUNDLE_IMAGE_NAME ?= $(IMAGE_NAME)-bundle
BUNDLE_IMG ?= $(IMAGE_REGISTRY)/$(REGISTRY_NAMESPACE)/$(BUNDLE_IMAGE_NAME):$(IMAGE_TAG)
PACKAGE_NAME ?= ocs-tls-profiles
SKIP_RANGE ?=
DEFAULT_CHANNEL ?= alpha
BUNDLE_DEFAULT_CHANNEL := --default-channel=$(DEFAULT_CHANNEL)
CHANNELS ?= $(DEFAULT_CHANNEL)
BUNDLE_CHANNELS := --channels=$(CHANNELS)

OPERATOR_SDK ?= $(LOCALBIN)/operator-sdk-$(OPERATOR_SDK_VERSION)
OPERATOR_SDK_VERSION ?= 1.42.2

.PHONY: bundle
bundle: kustomize operator-sdk manifests
	$(OPERATOR_SDK) generate kustomize manifests -q --interactive=false
	cd config/manifests && $(KUSTOMIZE) edit add patch --name ocs-tls-profiles.v0.0.0 --kind ClusterServiceVersion\
		--patch '[{"op": "add", "path": "/metadata/annotations/olm.skipRange", "value": "$(SKIP_RANGE)"}]' && \
		$(KUSTOMIZE) edit add patch --name ocs-tls-profiles.v0.0.0 --kind ClusterServiceVersion\
		--patch '[{"op": "replace", "path": "/spec/replaces", "value": "$(REPLACES)"}]'
	$(KUSTOMIZE) build config/manifests | $(OPERATOR_SDK) generate bundle \
		--overwrite --manifests --metadata --package $(PACKAGE_NAME) --version $(VERSION) \
		$(BUNDLE_DEFAULT_CHANNEL) $(BUNDLE_CHANNELS)
	cd config/manifests && yq -i 'del(.patches)' kustomization.yaml
	hack/update-csv-timestamp.sh
	$(OPERATOR_SDK) bundle validate ./bundle

.PHONY: bundle-build
bundle-build: bundle ## Build the bundle image.
	$(CONTAINER_TOOL) build -f bundle.Dockerfile -t $(BUNDLE_IMG) .

.PHONY: bundle-push
bundle-push: ## Push bundle image with the manager.
	$(CONTAINER_TOOL) push $(BUNDLE_IMG)

.PHONY: operator-sdk
operator-sdk: ## Download operator-sdk locally.
	@test -f $(OPERATOR_SDK) && echo "$(OPERATOR_SDK) already exists. Skipping download." && exit 0 ;\
	echo "Downloading $(OPERATOR_SDK)" ;\
        set -e ;\
        mkdir -p $(dir $(OPERATOR_SDK)) ;\
        OS=$(shell go env GOOS) && ARCH=$(shell go env GOARCH) && \
        curl -sSLo $(OPERATOR_SDK) https://github.com/operator-framework/operator-sdk/releases/download/v${OPERATOR_SDK_VERSION}/operator-sdk_$${OS}_$${ARCH} ;\
        chmod +x $(OPERATOR_SDK)
