
Release Checklist
=================


Prerequisites
-------------

Building Katzenpost has the following prerequisites:

* Some familiarity with building Go binaries.
* `Go <https://golang.org>`_ 1.9 or later.
* A recent version of `dep <https://github.com/golang/dep>`_.
* A recent version of `goreleaser <https://goreleaser.com>`_.



Katzenpost release process
--------------------------

* ensure local copies of all repositories are on master, up-to-date

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


* bump version tags for each repository
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
    * git commit changes to Gopkg.toml file

  * update vendoring
  .. code:: bash

      cd $GOPATH/github.com/katzenpost/daemons
      dep ensure

* commit and tag the changes to the daemons repo
.. code:: bash

   git commit -a -m "dep ensure"
   git tag v0.0.1

* use goreleaser to build binaries and packages
.. code:: bash

   cd $GOPATH/github.com/katzenpost/daemons
   goreleaser --rm-dist

* if all went well then push the release tag
.. code:: bash

   git push origin v0.0.1

* update docs respository's releases.rst to reflect reality

  * cd $GOPATH/src/github.com/katzenpost/docs
  * edit releases.rst
    * update heading, date, changes info



Katzenpost "playground" release process
---------------------------------------

After the above Katzenpost release process is performed
you can then create a new Playground release of the
Katzenpost client(s) using this procedure:

1. Update the vendor directory with the latest
   from the above release which you just performed:
.. code:: bash

   cd $GOPATH/github.com/katzenpost/playground
   rm -rf vendor
   cp -a ../daemons/vendor .
   git commit -a -m 'Add version v0.0.X of daemons/vendor'

2. Tag the current release with the playground version number:
.. code:: bash

   git tag v0.0.1

3. Build the release binaries and packages:
.. code:: bash

   goreleaser --rm-dist

4. If all went well then push the tag and commit:
.. code:: bash

   git push origin master
   git push origin v0.0.1
