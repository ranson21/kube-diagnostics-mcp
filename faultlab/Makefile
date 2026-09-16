# kube-diagnostics-mcp fault lab. Run from anywhere: `make -C faultlab <target>`.
CLUSTER   ?= kube-diag
NAMESPACE ?= faultlab
BASE_URL  ?= http://localhost:30080
DURATION  ?= 120
KUBECTL   ?= kubectl
# k8s = plain lab; k8s-probe = lab + kube-diagnostics probe sidecars + RUM ingest
KUSTOMIZE_DIR ?= k8s-probe
KIND      ?= kind
DOCKER    ?= docker

IMAGES := faultlab/proxy:dev faultlab/catalog-service:dev faultlab/order-service:dev faultlab/order-service:latest

.PHONY: help build load deploy undeploy status load-test clean cluster delete-cluster all probe-token

help:
	@echo "targets: cluster build load deploy status load-test undeploy clean delete-cluster all"
	@echo "  BASE_URL=$(BASE_URL) DURATION=$(DURATION)s CLUSTER=$(CLUSTER)"

## Create the kind cluster with the NodePort mapping (host :30080 -> proxy).
cluster:
	$(KIND) get clusters 2>/dev/null | grep -qx '$(CLUSTER)' || $(KIND) create cluster --config kind-config.yaml

delete-cluster:
	$(KIND) delete cluster --name $(CLUSTER)

## Build all three images. Java + Angular compile inside multi-stage Docker builds (no local toolchain needed).
build:
	DOCKER_BUILDKIT=1 $(DOCKER) build -f proxy/Dockerfile           -t faultlab/proxy:dev           ..   # context = repo root (rum-client)
	DOCKER_BUILDKIT=1 $(DOCKER) build -f catalog-service/Dockerfile -t faultlab/catalog-service:dev catalog-service
	DOCKER_BUILDKIT=1 $(DOCKER) build -f order-service/Dockerfile   -t faultlab/order-service:dev   order-service
	# the order-service Deployment deliberately uses the mutable ":latest" tag (see README fault table)
	$(DOCKER) tag faultlab/order-service:dev faultlab/order-service:latest

## Load images into the kind cluster (no registry needed).
load:
	$(KIND) load docker-image --name $(CLUSTER) $(IMAGES)

## Generate the probe token file the k8s-probe overlay needs (git-ignored). Set PROBE_TOKEN to reuse the hub's.
probe-token: k8s-probe/probe-token.yaml
k8s-probe/probe-token.yaml: k8s-probe/probe-token.example.yaml
	TOKEN="$${PROBE_TOKEN:-$$(openssl rand -hex 32)}"; sed "s/REPLACE_WITH_RANDOM_PROBE_TOKEN/$$TOKEN/" $< > $@; echo "wrote $@"

deploy: probe-token
	$(KUBECTL) apply -k $(KUSTOMIZE_DIR)
	@echo "waiting for postgres..."
	$(KUBECTL) -n $(NAMESPACE) rollout status statefulset/postgres --timeout=180s
	@echo "waiting for services (catalog-service is CPU-throttled and can take 1-3 min)..."
	$(KUBECTL) -n $(NAMESPACE) rollout status deploy/order-service   --timeout=300s
	$(KUBECTL) -n $(NAMESPACE) rollout status deploy/catalog-service --timeout=300s
	$(KUBECTL) -n $(NAMESPACE) rollout status deploy/proxy           --timeout=120s
	@echo "proxy: $(BASE_URL)/   (kind-config.yaml maps host 30080 -> NodePort 30080)"

undeploy:
	$(KUBECTL) delete -k $(KUSTOMIZE_DIR) --ignore-not-found

status:
	$(KUBECTL) -n $(NAMESPACE) get pods,svc,endpoints,ingress -o wide

## Hit the faulty endpoints for DURATION seconds to make every symptom show up.
load-test:
	BASE_URL=$(BASE_URL) DURATION=$(DURATION) ./scripts/load-test.sh

## Remove the lab from the cluster and delete local images/build output. Does not delete the cluster.
clean: undeploy
	-$(DOCKER) rmi $(IMAGES)
	rm -rf angular-app/dist angular-app/.angular catalog-service/target order-service/target

all: cluster build load deploy
