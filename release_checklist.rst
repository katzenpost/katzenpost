
Release Checklist
=================

Prerequisites
-------------

Building Katzenpost has the following prerequisites:

* Some familiarity with building Go binaries.
* `Go <https://golang.org>`_ 1.9 or later.
* A recent version of `dep <https://github.com/golang/dep>`_.


Building
--------

* ensure local copies of all respositories are on master, up-to-date

.. code:: bash

   cd $GOPATH/src/github.com/katzenpost/core
   git checkout master
   git pull origin master


.. code:: bash

   cd $GOPATH/src/github.com/katzenpost/server
   git checkout master
   git pull origin master


.. code:: bash

   cd $GOPATH/src/github.com/katzenpost/minclient
   git checkout master
   git pull origin master


.. code:: bash

   cd $GOPATH/src/github.com/katzenpost/mailproxy
   git checkout master
   git pull origin master


.. code:: bash

   cd $GOPATH/src/github.com/katzenpost/authority
   git checkout master
   git pull origin master


.. code:: bash

   cd $GOPATH/src/github.com/katzenpost/daemons
   git checkout master
   git pull origin master

    
* run all tests and ensure they pass

.. code:: bash

   cd $GOPATH/src/github.com/katzenpost/core
   go test -v ./...


.. code:: bash

   cd $GOPATH/src/github.com/katzenpost/server
   go test -v ./...


.. code:: bash

   cd $GOPATH/src/github.com/katzenpost/minclient
   go test -v ./...


.. code:: bash

   cd $GOPATH/src/github.com/katzenpost/mailproxy
   go test -v ./...


.. code:: bash

   cd $GOPATH/src/github.com/katzenpost/authority
   go test -v ./...


* bumb version tags for each repository
  (replace v0.0.1 with bumped version)


.. code:: bash

   cd $GOPATH/src/github.com/katzenpost/core
   git tag v0.0.1
   git push origin v0.0.1


.. code:: bash

   cd $GOPATH/src/github.com/katzenpost/authority
   git tag v0.0.1
   git push origin v0.0.1


.. code:: bash

   cd $GOPATH/src/github.com/katzenpost/minclient
   git tag v0.0.1
   git push origin v0.0.1


.. code:: bash

    cd $GOPATH/src/github.com/katzenpost/mailproxy
    git tag v0.0.1
    git push origin v0.0.1


.. code:: bash

    cd $GOPATH/src/github.com/katzenpost/server
    git tag v0.0.1
    git push origin v0.0.1


* update daemons repository's vending

  * edit Gopkg.toml vendoring file to use the latest version tag for
    each repository

    * edit https://github.com/katzenpost/daemons/blob/master/Gopkg.toml

  * update vendoring
  .. code:: bash

      cd $GOPATH/github.com/katzenpost/daemons
      dep ensure

* build the binaries
.. code:: bash

    (cd authority/nonvoting; go build)
    (cd server; go build)
    (cd mailproxy; go build)

* commit and tag the changes to the daemons repo
.. code:: bash

   git commit -a -m "dep ensure"
   git tag v0.0.1
   git push origin v0.0.1

* update docs respository's releases.rst to reflect reality

  * cd $GOPATH/src/github.com/katzenpost/docs
  * edit releases.rst
    * update heading, date, changes info
