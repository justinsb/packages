push:
	docker buildx build --push --progress=plain  --tag justinsb/kinspire-server -f images/kinspire-server/Dockerfile .
	docker buildx build --push --progress=plain  --tag justinsb/kinspire-sidecar -f images/kinspire-sidecar/Dockerfile .

bounce:
	 kubectl delete pod -n auth-system -l app=kinspire-server
	 kubectl delete pod -n auth-system -l app=kinspire-sidecar
