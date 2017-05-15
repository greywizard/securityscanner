PACKAGE  = securityscanner
DATE    ?= $(shell date +%FT%T%z)
VERSION ?= $(shell git describe --tags --always --dirty --match=v* 2> /dev/null || \
			cat $(CURDIR)/.version 2> /dev/null || echo v0)
BIN      = $(GOPATH)/bin
BASE     = $(GOPATH)/src/github.com/greywizard/$(PACKAGE)
PKGS     = $(or $(PKG),$(shell cd $(BASE) && env GOPATH=$(GOPATH) $(GO) list ./... | grep -v "/vendor/" | grep -v "/cmd/"))
TESTPKGS = $(shell env GOPATH=$(GOPATH) $(GO) list -f '{{ if .TestGoFiles }}{{ .ImportPath }}{{ end }}' $(PKGS))

GO       = go
GODOC    = godoc
GOFMT    = gofmt
GOVENDOR = govendor
TIMEOUT  = 15
V = 0
Q = $(if $(filter 1,$V),,@)
M = $(shell printf "\033[34;1m▶\033[0m")

.PHONY: build
build: ; $(info $(M) building executable…) @ ## Build program binary
	 cd $(BASE) && $(GO) build \
		-tags release \
		-ldflags '-X $(PACKAGE)/cmd.Version=$(VERSION) -X $(PACKAGE)/cmd.BuildDate=$(DATE)' \
		-o bin/$(PACKAGE) cmd/scannerServer.go

vendor-install : ; $(info $(M) Installing vendor packages…) @ ## Install vendor packages
	 cd $(BASE) && govendor install +vendor,^program

# Tools

GOVENDOR = $(BIN)/govendor
$(BIN)/govendor: | $(BASE) ; $(info $(M) building govendor…)
	$Q go get github.com/kardianos/govendor

GOLINT = $(BIN)/golint
$(BIN)/golint: | $(BASE) ; $(info $(M) building golint…)
	$Q go get github.com/golang/lint/golint

GOCOVMERGE = $(BIN)/gocovmerge
$(BIN)/gocovmerge: | $(BASE) ; $(info $(M) building gocovmerge…)
	$Q go get github.com/wadey/gocovmerge

GOCOV = $(BIN)/gocov
$(BIN)/gocov: | $(BASE) ; $(info $(M) building gocov…)
	$Q go get github.com/axw/gocov/...

GOCOVXML = $(BIN)/gocov-xml
$(BIN)/gocov-xml: | $(BASE) ; $(info $(M) building gocov-xml…)
	$Q go get github.com/AlekSi/gocov-xml

GO2XUNIT = $(BIN)/go2xunit
$(BIN)/go2xunit: | $(BASE) ; $(info $(M) building go2xunit…)
	$Q go get github.com/tebeka/go2xunit

# Tests
test: ; $(info $(M) running $(NAME:%=% )tests…) ## Run tests
	$Q cd $(BASE) && $(GO) test -timeout $(TIMEOUT)s $(ARGS) $(TESTPKGS)

test-xml: $(BASE) $(GO2XUNIT) ; $(info $(M) running $(NAME:%=% )tests…) @ ## Run tests with xUnit output
	$Q cd $(BASE) && 2>&1 $(GO) test -timeout 20s -v $(TESTPKGS) | tee test/tests.output
	$(GO2XUNIT) -fail -input test/tests.output -output test/tests.xml


COVERAGE_MODE = atomic
COVERAGE_PROFILE = $(COVERAGE_DIR)/profile.out
COVERAGE_XML = $(COVERAGE_DIR)/coverage.xml
COVERAGE_HTML = $(COVERAGE_DIR)/index.html
.PHONY: test-coverage test-coverage-tools
test-coverage-tools: | $(GOCOVMERGE) $(GOCOV) $(GOCOVXML)
test-coverage: COVERAGE_DIR := $(CURDIR)/test/coverage.$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
test-coverage: test-coverage-tools | $(BASE) ; $(info $(M) running coverage tests…) @ ## Run coverage tests
	$Q mkdir -p $(COVERAGE_DIR)/coverage
	$Q cd $(BASE) && for pkg in $(TESTPKGS); do \
		$(GO) test \
			-coverpkg=$$($(GO) list -f '{{ join .Deps "\n" }}' $$pkg | \
					grep '^$(PACKAGE)/' | grep -v '^$(PACKAGE)/vendor/' | \
					tr '\n' ',')$$pkg \
			-covermode=$(COVERAGE_MODE) \
			-coverprofile="$(COVERAGE_DIR)/coverage/`echo $$pkg | tr "/" "-"`.cover" $$pkg ;\
	 done
	$Q $(GOCOVMERGE) $(COVERAGE_DIR)/coverage/*.cover > $(COVERAGE_PROFILE)
	$Q $(GO) tool cover -html=$(COVERAGE_PROFILE) -o $(COVERAGE_HTML)
	$Q $(GOCOV) convert $(COVERAGE_PROFILE) | $(GOCOVXML) > $(COVERAGE_XML)


.PHONY: lint
lint: $(BASE) $(GOLINT) ; $(info $(M) running golint…) @ ## Run golint
	$Q cd $(BASE) && ret=0 && for pkg in $(PKGS); do \
		test -z "$$($(GOLINT) $$pkg | tee /dev/stderr)" || ret=1 ; \
	 done ; exit $$ret

# Checks
check-dependencies: ; $(info $(M) Checking dependencies…) @ ## Check dependend tools
	go test ./securityscanner/plugins/ip -run TestIpPlugin_CheckDatabase
	go test ./securityscanner/plugins/wappalyzer -run TestDockerImageExists
	go test ./securityscanner/plugins/https -run TestDocker*

check-configuration: ; $(info $(M) Checking configuration…) @ ## Check configuration
	go test ./securityscanner/plugins/blacklist -run TestBlacklistPlugin_Configuration
	go test ./securityscanner/plugins/ip -run TestIpPlugin_Configuration
	go test ./securityscanner/plugins/pagespeed -run TestPagespeedPlugin_Configuration

# Misc
.PHONY: fmt
fmt: ; $(info $(M) running gofmt…) @ ## Run gofmt on all source files
	@ret=0 && for d in $$($(GO) list -f '{{.Dir}}' ./... | grep -v /vendor/); do \
		$(GOFMT) -l -w $$d/*.go || ret=$$? ; \
	 done ; exit $$ret


.PHONY: clean
clean: ; $(info $(M) cleaning…)	@ ## Cleanup everything
	cd $(BASE)
	@rm -rf bin
	@rm -rf test

.PHONY: help
help:
	@grep -E '^[ a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m \t%s\n", $$1, $$2}'

.PHONY: version
version: ## Print current version
	@echo $(VERSION)