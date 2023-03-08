DOCKER_COMPOSE=docker-compose -p crick
RUN_MIGRATE=$(DOCKER_COMPOSE) -f docker-compose.yml -f docker-compose.tools.yml run --rm migrate

default: help

dev: ## start the API with Docker
	@FLASK_DEBUG=1 FLASK_APP=server.py flask run
	@echo "\033[92mYou can browse the application at: http://localhost:3000\033[0m"
.PHONY: dev

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
.PHONY: help
