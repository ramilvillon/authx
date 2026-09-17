# Local development. Thin wrapper over `docker compose` and the deno tasks in
# deno.json — those stay the source of truth; this only sequences them.
.DEFAULT_GOAL := help
.PHONY: help setup up stop down status logs db-shell studio migrate seed bootstrap dev test check db-reset

help: ## List targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-10s %s\n", $$1, $$2}'

# `deno --env-file` keeps the FIRST value of a duplicated key, so appending keys
# after the template's empty `JWT_PRIVATE_KEY=` would leave them empty. Strip
# the empty lines first.
setup: ## Create .env from the template with a fresh JWT keypair (skips if .env exists)
	@if [ -f .env ]; then echo ".env exists, leaving it alone"; else \
		grep -vE '^JWT_(PRIVATE|PUBLIC)_KEY=$$' .env.example > .env && \
		deno task -q keys:gen >> .env && echo "wrote .env"; fi

up: ## Start MySQL + Mailpit and wait until healthy
	docker compose up -d --wait mysql mailpit

stop: ## Stop containers, keep data
	docker compose stop

down: ## Remove containers AND the database volume (data is lost)
	docker compose down -v

status: ## Show container status
	docker compose ps

logs: ## Follow container logs
	docker compose logs -f

db-shell: ## Open a mysql shell as the app user
	docker compose exec mysql mysql -uapp -papp app

studio: up ## Browse/edit the DB in Drizzle Studio (https://local.drizzle.studio)
	deno run -A --env-file=.env npm:drizzle-kit studio

migrate: up ## Apply migrations
	deno task db:migrate

seed: up ## Seed platform tenant + bootstrap admin (idempotent)
	deno task db:seed

bootstrap: setup migrate seed ## First run: .env, containers, migrations, seed

dev: up ## Run the API with --watch
	deno task dev

test: ## Unit + integration tests (no containers needed)
	deno task test:unit && deno task test:integration

check: ## fmt, lint, typecheck
	deno task check:all

db-reset: down migrate seed ## Wipe the database and rebuild it from migrations
