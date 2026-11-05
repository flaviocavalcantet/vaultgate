.PHONY: up down test lint migrate tf-local obs-check auth-check vault-check token seed-policies k3d-up k3d-images k3d-check k3d-down

up:          ## Start the local stack (services, dependencies and Prometheus/Loki/Tempo/Alloy/Grafana)
	docker compose up --build -d

down:
	docker compose down -v

test:        ## Run every test suite
	cd api && pytest -q
	cd gateway && pytest -q
	cd scanner && go test ./...

lint:
	ruff check api gateway
	ruff format --check api gateway
	cd scanner && test -z "$$(gofmt -l .)" && go vet ./...

migrate:     ## Apply database migrations (uses VAULTGATE_DATABASE_URL, defaults to local Postgres)
	cd api && alembic upgrade head

obs-check:   ## Check Prometheus config and alert rules (with unit tests), Loki, Tempo, Alloy and dashboards (needs Docker)
	docker run --rm -v $(CURDIR)/observability/prometheus:/etc/prometheus:ro --entrypoint promtool prom/prometheus:v3.1.0 check config /etc/prometheus/prometheus.yml
	docker run --rm -v $(CURDIR)/observability/prometheus/rules:/rules:ro -w /rules --entrypoint promtool prom/prometheus:v3.1.0 test rules vaultgate_test.yml
	docker run --rm -v $(CURDIR)/observability/loki/loki.yml:/cfg/loki.yml:ro grafana/loki:3.3.2 -config.file=/cfg/loki.yml -verify-config
	docker run --rm -v $(CURDIR)/observability/tempo/tempo.yml:/cfg/tempo.yml:ro grafana/tempo:2.6.1 -config.file=/cfg/tempo.yml -config.verify=true
	docker run --rm -v $(CURDIR)/observability/alloy:/cfg:ro grafana/alloy:v1.5.1 fmt -t /cfg/config.alloy
	docker run --rm -v $(CURDIR)/observability/alloy:/cfg:ro grafana/alloy:v1.5.1 fmt -t /cfg/kubernetes.alloy
	python3 scripts/check_dashboards.py observability/grafana/dashboards

token:       ## Log in through Keycloak in the browser and print an access token (TOKEN=$$(make -s token))
	@python3 scripts/vaultgate_login.py

auth-check:  ## Log in as every seed user through Keycloak and call the API with the tokens (needs Docker)
	docker compose up -d --build keycloak api
	python3 scripts/keycloak_smoke.py http://localhost:8080 --api http://localhost:8000

vault-check: ## Upload and download a file through the real stack, check it is encrypted in S3 and traced (needs Docker and Terraform)
	docker compose up -d --build postgres localstack keycloak mailpit api gateway scanner alloy
	for i in $$(seq 60); do curl -sf http://localhost:4566/_localstack/health >/dev/null && break; sleep 2; done
	$(MAKE) tf-local
	python3 scripts/seed_policies.py
	python3 scripts/vault_e2e.py

seed-policies: ## Allow every signed-in user everything (local development only; access is denied by default)
	python3 scripts/seed_policies.py

tf-local:    ## Apply Terraform against LocalStack (run `make up` first)
	cd infra/terraform/envs/local && terraform init && terraform apply -auto-approve

k3d-up:      ## Local Kubernetes: k3d cluster, images in its registry, Argo CD syncing this repo (needs Docker, k3d, kubectl, Terraform)
	scripts/k3d.sh up

k3d-images:  ## Rebuild the images, push them to the cluster's registry and restart the pods
	scripts/k3d.sh images

k3d-check:   ## The vault end-to-end check against the cluster, plus Argo CD, autoscaler and network policy checks
	scripts/k3d.sh check

k3d-down:    ## Delete the local cluster
	scripts/k3d.sh down
