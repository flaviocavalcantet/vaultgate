.PHONY: up down test lint migrate tf-local

up:          ## Start the local stack (Postgres, LocalStack, Keycloak, API, gateway)
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

tf-local:    ## Apply Terraform against LocalStack (run `make up` first)
	cd infra/terraform/envs/local && terraform init && terraform apply -auto-approve
