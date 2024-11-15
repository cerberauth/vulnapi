PYTHON = python3
BIN = vulnapi
.DEFAULT_GOAL := $(BIN)
MIN_GO_VERSION = go1.23.0

.PHONY: check_versions clean
check_versions:
ifeq (, $(shell which go))
	$(error "No go command in $(PATH), consider doing apt-get install golang-go")
endif
ifeq (, $(shell which ruby))
	$(error "No ruby command in $(PATH), consider doing apt-get install ruby")
endif
ifeq (, $(shell which $(PYTHON)))
	PYTHON=python
endif
ifeq (, $(shell which $(PYTHON)))
	$(error "No python/python3 command in $(PATH), consider doing apt-get install python3")
endif
ifneq (0, $(shell $(PYTHON) ./scripts/verify_go_version.py $(MIN_GO_VERSION) 2>&1 >/dev/null; echo $$?))
	$(error "Your go version is too old/invalid !")
endif

$(BIN):	check_versions
	go build -o $(BIN)

clean:	check_versions
	go clean
