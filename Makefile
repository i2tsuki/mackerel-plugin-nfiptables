GO ?= go

GOARCH := $(shell $(GO) env GOARCH)
GOHOSTARCH := $(shell $(GO) env GOHOSTARCH)

DEP ?= $(GOPATH)/bin/dep
GOX ?= $(GOPATH)/bin/gox
GORELEASER ?= $(GOPATH)/bin/goreleaser
GHR ?= $(GOPATH)/bin/ghr
STATICCHECK ?= $(GOPATH)/bin/staticcheck
LATEST_TAG = $(shell git describe --abbrev=0 --tags)
pkgs = $(shell $(GO) list ./... | grep -v /vendor/)
arch = "arm 386 amd64"
os = "freebsd linux netbsd openbsd"

dep:
	@echo ">> resolve package dependency"
	@$(DEP) ensure

style:
	@echo ">> checking code style"
	@! gofmt -d $(shell find . -path ./vendor -prune -o -name '*.go' -print) | grep '^'

format:
	@echo ">> formatting code"
	@$(GO) fmt $(pkgs)

vet:
	@echo ">> vetting code"
	@$(GO) vet $(pkgs)

staticcheck: $(STATICCHECK)
	@echo ">> running staticcheck"
	@$(STATICCHECK) $(pkgs)

build:
	@echo ">> building binaries"
	@$(GO) build .

cross:
	@echo ">> cross building binaries"
	@$(GORELEASER) --skip-publish

release:
	@echo ">> building release zip archive"
	@for i in $$(find ./dist -mindepth 1 -type d -printf '%f\n'); do zip -j ./dist/$$i.zip ./dist/$$i/*; done
	@for i in $$(find ./dist -mindepth 1 -name '*.zip' -type f -printf '%f\n'); do $(GHR) -replace $(LATEST_TAG) ./dist/$$i; done

clean:
	@rm -rf ./dist

$(GOPATH)/bin/dep:
	@GOOS= GOARCH= $(GO) get -u github.com/golang/dep/cmd/dep

$(GOPATH)/bin/goreleaser:
	@GOOS= GOARCH= $(GO) get -u github.com/goreleaser/goreleaser

$(GOPATH)/bin/staticcheck:
	@GOOS= GOARCH= $(GO) get -u honnef.co/go/tools/cmd/staticcheck

.PHONY: dep style format build vet tarball staticcheck
