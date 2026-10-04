PYTHON ?= python3

.PHONY: build test

build:
	$(PYTHON) build.py

test:
	$(PYTHON) -m unittest
