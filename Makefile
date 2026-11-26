PYTHON ?= python
PYTEST ?= $(PYTHON) -m pytest

.PHONY: all build build-vm test test-dsl clean

all: build-vm

build: build-vm

build-vm:
	$(PYTHON) -m runtime.frida.build --output build/frida-vm

test: test-dsl

test-dsl:
	$(PYTEST) tests/test_dsl.py tests/test_dsl_fine.py tests/test_dsl_vm.py tests/test_dsl_resolve.py tests/test_dsl_x86.py

clean:
	rm -rf build
