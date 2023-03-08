DOCKER_COMPOSE=docker-compose -p crick
RUN_MIGRATE=$(DOCKER_COMPOSE) -f docker-compose.yml -f docker-compose.tools.yml run --rm migrate

default: help

dev: ## start the API with Docker
	@docker-compose -p crick up --build -d
	@echo "\033[92mYou can browse the application at: http://localhost:8000\033[0m"
.PHONY: dev

production:
	@APP_ENV=production docker-compose -p crick up --build -d
	@echo "\033[92mYou can browse the application at: http://localhost:8000\033[0m"
.PHONY: production

logs: ## show the API logs
	$(DOCKER_COMPOSE) logs -f api
.PHONY: logs

migrate-up: ## apply database migrations
	$(RUN_MIGRATE) up
.PHONY: migrate-up

migrate-version: ## show database migration version
	$(RUN_MIGRATE) version
.PHONY: migrate-version

down: ## run docker-compose down
	$(DOCKER_COMPOSE) down
.PHONY: logs

test: ## run the test suite
	go test -v $$(go list ./... | grep -v /vendor/)
.PHONY: test

exec-db: ## exec the database container
	@echo "\033[92mconnecting to database.. try 'select * from users;' for a start\033[0m"
	$(DOCKER_COMPOSE) exec db sh -c "psql -h localhost -p 5432 -U crick crick"
.PHONY: exec-db

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
.PHONY: help
