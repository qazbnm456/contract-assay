# contract-assay — the commands a submission is built with.
#
# Two audiences, and the split is the first thing to understand:
#
#   make help / setup / corpus / run / score / self-check
#       A participant preparing a submission. Everything here runs on your
#       machine against the PUBLIC split. Nothing here talks to an arena.
#
#   make check / format
#       A contributor to the benchmark itself.
#
# Every target is a thin wrapper around one documented command. Where a target
# would have to decide something on your behalf it asks instead, because a
# Makefile that quietly picks a model, a budget or a weighting has made the
# statement `docs/api.md` §8 says you have to make yourself.

PY ?= .venv/bin/python
CLI ?= .venv/bin/contract-assay

RECORDS  ?= corpus/records
CHECKOUT ?= checkout
OUT      ?= runs.jsonl
SCORE    ?= score.json

.DEFAULT_GOAL := help
.PHONY: help setup corpus run score self-check check format clean

help: ## Show this list.
	@echo "contract-assay — building a submission"
	@echo
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk -F':.*?## ' '{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'
	@echo
	@echo "Variables: RECORDS=$(RECORDS) CHECKOUT=$(CHECKOUT) OUT=$(OUT)"
	@echo "Start with: make setup && make corpus"

setup: ## Install the benchmark and check the install.
	$(PY) -m pip install -q -e . --group dev
	@$(CLI) --help >/dev/null && echo "contract-assay is installed."
	@echo "Next: make corpus"

corpus: ## Build the source checkout the records point at.
	@# Every figure rests on re-reading the quotes a submission cites, so a
	@# checkout is not optional. `fetch` verifies each file's digest against
	@# the pin, which is what makes two people's runs comparable at all.
	$(CLI) fetch $(RECORDS) --source-root $(CHECKOUT)
	@echo "Next: write a harness, then: make run MANIFEST=your.json"

run: ## Run your harness over the corpus. MANIFEST=... [MODEL_CALLER=...]
ifndef MANIFEST
	$(error MANIFEST is unset. Point it at your submission manifest: make run MANIFEST=my-harness.json)
endif
	@# No model is called unless you name one. A deterministic submission is a
	@# real submission and this benchmark's own control group, so the default
	@# is not a fallback -- see `contract-assay run --help`.
	$(CLI) run --manifest $(MANIFEST) --records $(RECORDS) \
		--source-root $(CHECKOUT) --out $(OUT) \
		$(if $(MODEL_CALLER),--model-caller $(MODEL_CALLER),)
	@echo "Next: make score"

score: ## Score your own runs. [WEIGHTS=weights.json]
	@# Without --weights there is no aggregate, and that is correct rather
	@# than broken: a weighting states what an exercise values and this engine
	@# ships none. The per-class figures are all there.
	$(CLI) score $(OUT) --records $(RECORDS) --source-root $(CHECKOUT) \
		--submission-id self --out $(SCORE) \
		$(if $(WEIGHTS),--weights $(WEIGHTS),)
	@echo "Wrote $(SCORE)"

self-check: corpus run score ## corpus, run and score in one go. MANIFEST=...
	@echo
	@echo "If scoring said predictions await adjudication, that is expected:"
	@echo "precision needs every prediction judged, and on your own machine"
	@echo "nothing has judged them. Read recall and bpref instead."

check: ## Lint, type-check and test the benchmark itself.
	.venv/bin/ruff check .
	.venv/bin/ruff format --check .
	.venv/bin/mypy
	.venv/bin/mypy tools
	$(PY) -m pytest -q -m offline --cov=contract_assay --cov-fail-under=90
	$(CLI) results results

format: ## Apply formatting.
	.venv/bin/ruff check --fix .
	.venv/bin/ruff format .

clean: ## Remove generated run and score files. Never touches the corpus.
	rm -f $(OUT) $(SCORE)
