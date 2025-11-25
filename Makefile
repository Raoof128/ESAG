PYTHON?=python
PIP?=$(PYTHON) -m pip
VENV?=.venv

.PHONY: install install-dev lint format test clean

install:
$(PIP) install --upgrade pip
$(PIP) install -r requirements.txt

install-dev: install
$(PIP) install -r requirements-dev.txt

lint:
ruff check .
black --check .

format:
black .

test:
$(PYTHON) -m pytest

clean:
rm -rf $(VENV) .pytest_cache __pycache__ */__pycache__ .ruff_cache .mypy_cache
