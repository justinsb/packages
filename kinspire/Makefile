GCP_PROJECT_ID ?= $(shell gcloud config get project)
IMAGE_REPO ?= gcr.io/$(GCP_PROJECT_ID)
IMAGE_TAG ?= latest

.PHONY: push
push:
	KO_DOCKER_REPO=${IMAGE_REPO}/kinspire-server ko build  --bare --tags ${IMAGE_TAG} ./cmd/kinspire-server/
	KO_DOCKER_REPO=${IMAGE_REPO}/kinspire-sidecar ko build  --bare --tags ${IMAGE_TAG} ./cmd/kinspire-sidecar/

.PHONY: apply
apply: push
	cat ./k8s/manifest.yaml | sed -e s~image-repo~${IMAGE_REPO}~g | kubectl apply -f -
	cat ./k8s/public-configmap.yaml | kubectl apply -f -

.PHONY: bounce
bounce:
	 kubectl delete pod -n auth-system -l app=kinspire-server
	 kubectl delete pod -n auth-system -l app=kinspire-sidecar


.PHONY: protoc-generate
protoc-generate:
	cd dev/build/protobuf; docker buildx build --tag dev-build-protobuf --load .
	docker run -v `pwd`:/workspace dev-build-protobuf buf generate
