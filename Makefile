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

run-pingpong: all
	bin/curvetls-server 127.0.0.1:9001 pb2GtjnuIuTH+hayKtRcTMg7O0fac7GP+/v9FgOqQd+w= PyDdLt+wYELY9U7NyxJZVuGcStGW7axlt6sfrBaqsvCo= & pid=$$! ; sleep 0.1 ; bin/curvetls-client 127.0.0.1:9001 pJdaFzGD2eRN6z3DziBErbzGeriy9WK5kN+sEIiqMzpY= PiYnKerHceX2ePqRYOiKb/mDooP4RyfdIFljC6Fgw2Rg= PyDdLt+wYELY9U7NyxJZVuGcStGW7axlt6sfrBaqsvCo= ; wait $$pid

test:
	GOPATH=$(PWD) go test

bench:
	GOPATH=$(PWD) go test -bench=.
