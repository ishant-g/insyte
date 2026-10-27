.DEFAULT_GOAL := help

.PHONY: help up down reset ps logs health test test-backend typecheck build clean

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-14s %s\n", $$1, $$2}'

up: ## Build and start the full stack in the background
	docker compose up -d --build

down: ## Stop the stack, keeping data volumes
	docker compose down

reset: ## Stop the stack and delete database/report volumes
	docker compose down -v

ps: ## Show container status
	docker compose ps

logs: ## Follow API, worker, and scheduler logs
	docker compose logs -f --tail=100 api worker beat

health: ## Print API health
	curl -fsS http://localhost:8000/health; echo

test: test-backend ## Run all checks

test-backend: ## Run backend tests in a throwaway Python container
	docker run --rm --user root \
		-v "$(CURDIR)/backend:/app" -w /app python:3.13-slim \
		bash -c "pip install -q -r requirements-dev.txt && pytest -q"

typecheck: ## Typecheck and build the frontend
	cd frontend && npm ci --no-audit --no-fund && npm run typecheck && npm run build

build: ## Build the backend and frontend images
	docker build -t insyte-api ./backend
	docker build -t insyte-frontend ./frontend

clean: ## Remove local Python/build caches
	docker run --rm -v "$(CURDIR):/src" alpine sh -c \
		"find /src -type d -name __pycache__ -prune -exec rm -rf {} +; \
		 rm -rf /src/backend/.ruff_cache /src/backend/.pytest_cache /src/frontend/dist"
