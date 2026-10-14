PY ?= python3
DB ?= injectionwatch.db
SITE ?= _site

.PHONY: help install lint fmt typecheck test cov check eval eval-full fixtures ext ext-package \
        demo warc-demo publish crawl-sample report serve mcp docker-build docker-run clean

help:  ## list targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | sed 's/:.*##/\t/' | sort

install:  ## editable install with all extras
	$(PY) -m pip install -e '.[api,llm,mcp,render,dev]'

lint:  ## ruff
	$(PY) -m ruff check .

fmt:  ## ruff autofix
	$(PY) -m ruff check --fix .

typecheck:  ## mypy
	$(PY) -m mypy

test: ext  ## build extension, run tests
	$(PY) -m pytest -q

cov: ext  ## tests with coverage gate (>= 85%)
	$(PY) -m pytest -q --cov --cov-report=term

check: lint typecheck cov  ## everything CI runs

eval:  ## precision/recall, static mode, all corpora
	$(PY) -m injectionwatch eval

eval-full:  ## static + static_css + rendered, writes reports/eval/latest.json
	$(PY) -m injectionwatch eval --rendered --details --json-out reports/eval/latest.json

fixtures:  ## regenerate dev fixture corpora (never touches the frozen held-out set)
	$(PY) scripts/make_fixtures.py
	$(PY) scripts/make_dev_fixtures.py

ext:  ## build the MV3 extension into extension/dist
	cd extension && npm run build

ext-package: ext  ## zip extension/dist for the Chrome Web Store
	cd extension && npm run package

demo:  ## local end-to-end demo against fixtures on 127.0.0.1 (no internet)
	$(PY) scripts/local_demo.py --db demo.db

warc-demo:  ## build a synthetic WARC from fixtures and scan it
	$(PY) scripts/make_synthetic_warc.py reports/synthetic.warc.gz
	$(PY) -m injectionwatch scan-warc reports/synthetic.warc.gz --db warc-demo.db --jsonl reports/synthetic_hits.jsonl

publish:  ## build the static GitHub Pages site from $(DB) into $(SITE)/
	$(PY) -m injectionwatch publish --db $(DB) --out $(SITE)

crawl-sample:  ## real polite crawl of the sample list (needs internet)
	$(PY) -m injectionwatch crawl data/sample_domains.csv --db $(DB) --limit 200 --json-summary reports/crawl_summary.json

report:
	$(PY) -m injectionwatch report --db $(DB)

serve:  ## run the API on 127.0.0.1:8000 (docs at /docs)
	$(PY) -m injectionwatch serve --db $(DB)

mcp:
	INJECTIONWATCH_DB=$(DB) $(PY) -m injectionwatch.mcp_server

docker-build:
	docker build -t injectionwatch:local .

docker-run:
	docker run --rm -p 8000:8000 -v $(PWD)/data-volume:/data injectionwatch:local

clean:
	rm -rf extension/dist extension/*.zip demo.db warc-demo.db .pytest_cache .mypy_cache .ruff_cache .coverage coverage.xml $(SITE)
