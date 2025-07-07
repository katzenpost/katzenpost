all: keygen encap decap test

keygen:
	go build examples/keygen/keygen.go

encap:
	go build examples/encap/encap.go

decap:
	go build examples/decap/decap.go

test: test.sh
	/bin/sh -n $<
	cat $< > $@
	chmod +x $@

clean:
	GOPATH=${CURDIR} go clean
	rm -f keygen encap decap test

.PHONY: keygen encap decap clean
