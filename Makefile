.PHONY: up down test lint migrate tf-local obs-check auth-check vault-check token seed-policies k3d-up k3d-images k3d-check k3d-zap k3d-browser dev-cert k3d-down load-test load-smoke load-report

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
	docker run --rm -v $(CURDIR)/observability/prometheus:/etc/prometheus:ro --entrypoint promtool prom/prometheus:v3.16.0 check config /etc/prometheus/prometheus.yml
	docker run --rm -v $(CURDIR)/observability/prometheus/rules:/rules:ro -w /rules --entrypoint promtool prom/prometheus:v3.16.0 test rules vaultgate_test.yml
	docker run --rm -v $(CURDIR)/observability/loki/loki.yml:/cfg/loki.yml:ro grafana/loki:3.7.9 -config.file=/cfg/loki.yml -verify-config
	docker run --rm -v $(CURDIR)/observability/tempo/tempo.yml:/cfg/tempo.yml:ro grafana/tempo:2.10.10 -config.file=/cfg/tempo.yml -config.verify=true
	docker run --rm -v $(CURDIR)/observability/alloy:/cfg:ro grafana/alloy:v1.21.3 fmt -t /cfg/config.alloy
	docker run --rm -v $(CURDIR)/observability/alloy:/cfg:ro grafana/alloy:v1.21.3 fmt -t /cfg/kubernetes.alloy
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

k3d-up:      ## Local Kubernetes: k3d cluster, images built and loaded into it, Argo CD syncing this repo (needs Docker, k3d, kubectl, Terraform)
	scripts/k3d.sh up

k3d-images:  ## Rebuild the images, load them into the cluster and restart the pods
	scripts/k3d.sh images

k3d-check:   ## The vault end-to-end check against the cluster, plus Argo CD, autoscaler and network policy checks, and negative tests
	scripts/k3d.sh check

k3d-zap:     ## OWASP ZAP against the cluster's API and gateway (reports in zap-reports/); run it last
	scripts/k3d.sh zap

k3d-browser: ## The web app's browser tests (Playwright and axe, from vaultgate-frontend) against the cluster (needs Node 22 and certutil)
	scripts/k3d.sh browser

dev-cert:    ## Copy the cluster's localhost certificate to ~/.vaultgate/dev-tls, for the frontend's `npm run dev:k3d`
	scripts/k3d.sh dev-cert

k3d-down:    ## Delete the local cluster
	scripts/k3d.sh down

# Load tests (M8, loadtest/): against the local cluster (`make k3d-up`), as the load users
# in the /load group. Needs `pip install -r loadtest/requirements.txt`. Locust's own exit
# code is ignored: loadtest/check.py decides, with Prometheus's view of the same minutes.
# VAULTGATE_LOAD_CLEANUP=1 removes each transferred object from LocalStack once its
# download checked out, so a run doesn't pile gigabytes of ciphertext into the cluster.
LOAD_RESULTS ?= loadtest/results
LOAD_PROFILE = 20 users (Transfers, ControlPlane and Documents weighted 3:2:1) for 6 minutes, uploads up to 128 MiB
# The API, the gateway and Keycloak serve TLS on the cluster (M9): Locust's clients trust
# its root.
PKI_DIR ?= $(or $(VAULTGATE_PKI_DIR),$(if $(CI),$(RUNNER_TEMP)/vaultgate-pki,$(HOME)/.vaultgate/pki))
LOCUST = VAULTGATE_LOAD_CLEANUP=1 VAULTGATE_CA_BUNDLE=$(PKI_DIR)/root-ca.crt VAULTGATE_KEYCLOAK=https://localhost:8080 locust -f loadtest/locustfile.py --headless --host https://localhost:8000 --exit-code-on-error 0

load-test:   ## Full load run against the local cluster: 20 users for 6 minutes; results in loadtest/results/
	mkdir -p $(LOAD_RESULTS)
	$(LOCUST) -u 20 -r 1 -t 6m --csv $(LOAD_RESULTS)/full --html $(LOAD_RESULTS)/full.html
	python3 loadtest/check.py $(LOAD_RESULTS)/full

load-report: ## The full run, then docs/load-testing.md and its charts from it (CI: load-report workflow)
	mkdir -p $(LOAD_RESULTS)
	$(LOCUST) -u 20 -r 1 -t 6m --csv $(LOAD_RESULTS)/full --html $(LOAD_RESULTS)/full.html
	python3 loadtest/report.py $(LOAD_RESULTS)/full --profile "$(LOAD_PROFILE)"

load-smoke:  ## Short load run with pass/fail thresholds (CI): 6 users for 90 s, uploads up to 32 MiB
	mkdir -p $(LOAD_RESULTS)
	VAULTGATE_LOAD_MAX_MIB=32 $(LOCUST) -u 6 -r 2 -t 90s --csv $(LOAD_RESULTS)/smoke
	python3 loadtest/check.py $(LOAD_RESULTS)/smoke
