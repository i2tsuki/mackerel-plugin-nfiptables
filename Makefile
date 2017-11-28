GO ?= go

GOARCH := $(shell $(GO) env GOARCH)
GOHOSTARCH := $(shell $(GO) env GOHOSTARCH)

DEP ?= $(GOPATH)/bin/dep
GOX ?= $(GOPATH)/bin/gox
STATICCHECK ?= $(GOPATH)/bin/staticcheck
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
	@mkdir -pv target
	@echo ">> cross building binaries"
	@$(GOX) -arch=$(arch) -os=$(os) -output=./target/{{.Dir}}_{{.OS}}_{{.Arch}}

zip:
	@echo ">> building release zip archive"
	@mkdir -pv target/release
	@for i in $$(find target -type f -printf '%f\n'); do zip ./target/release/$$i.zip ./target/$$i; done

$(GOPATH)/bin/dep:
	@GOOS= GOARCH= $(GO) get -u github.com/golang/dep/cmd/dep

$(GOPATH)/bin/gox:
	@GOOS= GOARCH= $(GO) get -u github.com/mitchellh/gox

$(GOPATH)/bin/staticcheck:
	@GOOS= GOARCH= $(GO) get -u honnef.co/go/tools/cmd/staticcheck

.PHONY: dep style format build vet tarball staticcheck
