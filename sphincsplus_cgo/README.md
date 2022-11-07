
What is this?
=============

CGO Go bindings to the Sphincs+ reference implementation.
Sphincs+ is a post quantum cryptographic signature scheme.

Learn more about Sphincs+ here: https://sphincs.org/

How to Build
============

Step 1
------

Build the Sphincs+ C library file:

```
cd sphincsplus/ref
make libsphincsplus.a
cd ../..
```

Sphincs+ CGO bindings Tests and Benchmarks
==========================================

```
go test -v
```

License
=======

### License

All included code is available under the CC0 1.0 Universal Public Domain Dedication.
