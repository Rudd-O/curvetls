.PHONY: deps fmt

deplist = src/github.com/golang/crypto \
	src/github.com/Rudd-O/curvetls

objlist = bin/curvetls-server \
	bin/curvetls-client \
	bin/curvetls-genkeypair

all: $(objlist)

deps: $(deplist)

src/github.com/Rudd-O/curvetls:
	mkdir -p `dirname $@`
	ln -s ../../.. $@

src/github.com/%:
	mkdir -p `dirname $@`
	cd `dirname $@` && git clone `echo $@ | sed 's|src/|https://|'`
	if [[ $@ == src/github.com/golang* ]] ; then mkdir -p src/golang.org/x ; ln -sf ../../../$@ src/golang.org/x/ ; fi

bin/%: deps
	GOPATH=$(PWD) go install github.com/Rudd-O/curvetls/cmd/`echo $@ | sed 's|bin/||'`

fmt:
	for f in *.go cmd/*/*.go ; do gofmt -w "$$f" || exit 1 ; done
