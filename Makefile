.PHONY: up down test lint migrate tf-local obs-check

up:          ## Start the local stack (services, dependencies and Prometheus/Loki/Alloy/Grafana)
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

obs-check:   ## Validate the Prometheus, Loki and Alloy configs with their own tools (needs Docker)
	docker run --rm -v $(CURDIR)/observability/prometheus:/cfg:ro --entrypoint promtool prom/prometheus:v3.1.0 check config /cfg/prometheus.yml
	docker run --rm -v $(CURDIR)/observability/loki/loki.yml:/cfg/loki.yml:ro grafana/loki:3.3.2 -config.file=/cfg/loki.yml -verify-config
	docker run --rm -v $(CURDIR)/observability/alloy:/cfg:ro grafana/alloy:v1.5.1 fmt /cfg/config.alloy > /dev/null

tf-local:    ## Apply Terraform against LocalStack (run `make up` first)
	cd infra/terraform/envs/local && terraform init && terraform apply -auto-approve
