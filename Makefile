# Reference card for usual actions in development environment.
#


.PHONY: help
help: ## Display callable targets.
	@echo "Reference card for usual actions in development environment."
	@echo "Here are available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'


.PHONY: develop
develop: ## Display callable targets.
	virtualenv -p python3 venv
	venv/bin/pip install -r requirements.txt
	venv/bin/pip install --editable .
	venv/bin/python
