default: test

format: ## Format python code
	ruff check --fix .
	ruff format .

lint: format ## Run code linter
	python -m ruff check .
	python -m ruff format --check .

test: lint ## Run unit tests
	pytest src

run-app: ## Run app at default port
	cd src; uvicorn app:app --host 0.0.0.0 --reload

run-arrow-server: ## Run arrow server
	cd src; python -m arrow_flight.server

run-arrow-client: ## Run arrow client
	cd src; python -m arrow_flight.client

run-test: ## Run test client
	./test.sh

start-keycloak: ## Start Keycloak container with admin/admin user
	docker run --rm -p 8080:8080 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak:24.0.4 start-dev

setup-keycloak: ## Setup Keycloak with a "poc" realm and an "app" client
	python keycloak_setup.py

help: ## Show this help
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-20s %s\n", $$1, $$2}'

