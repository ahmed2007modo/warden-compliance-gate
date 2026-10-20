# Warden — developer tasks (Windows PowerShell / POSIX-neutral)
# Targets Python 3.12. Adjust VENVPY if your interpreter differs.

PYTHON = .venv/Scripts/python.exe
PIP = $(PYTHON) -m pip

.PHONY: help install dev fmt lint test benchmark api clean

help:
	@echo "make install    - create venv + install services/api[dev]"
	@echo "make lint       - ruff check"
	@echo "make test       - run pytest suite"
	@echo "make benchmark  - regenerate fixtures + run evaluation, save report"
	@echo "make api        - run uvicorn locally"

install:
	$(PYTHON) -m pip install -e services/api[dev]

fmt:
	$(PYTHON) -m ruff check --fix services/api tests scripts

lint:
	$(PYTHON) -m ruff check services/api tests scripts

test:
	$(PYTHON) -m pytest

benchmark:
	$(PYTHON) scripts/make_fixtures.py
	$(PYTHON) scripts/run_benchmark.py --save

api:
	$(PYTHON) -m uvicorn app.main:app --app-dir services/api --reload

clean:
	$(PYTHON) -m pytest --cache-clear -q
	-$(PYTHON) -m ruff cache clean
