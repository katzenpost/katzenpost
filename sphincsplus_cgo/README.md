
What is this?
=============

CGO Go bindings to the Sphincs+ reference implementation.
Sphincs+ is a post quantum cryptographic signature scheme.

Learn more about Sphincs+ here: https://sphincs.org/

How to Build
============

Step 1
------

Get the katzenpost fork of the sphincs+ reference implementation
(modified the Makefile to build shared object library file):

```
git clone https://github.com/katzenpost/sphincsplus.git
```

Step 2
------

Build the Sphincs+ C shared library file:

```
cd sphincsplus/ref
make libsphincsplus.so
sudo make install
sudo ldconfig
cd ../..
```

Step 3
------

If the sphincsplus reference library is properly installed in /usr/local/... then
running the unit tests should work:

```
go test -v

```

Include sphincsplug_cgo in your Golang project:

```
import (
	sphincs "github.com/katzenpost/sphincsplus_cgo"
)
```


Sphincs+ CGO bindings Tests and Benchmarks
==========================================

The the env vars as specified above in the previous section of this readme. Then run:

```
go test -v
```


License
=======

### License

All included code is available under the CC0 1.0 Universal Public Domain Dedication.
