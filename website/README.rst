Katzenpost Website
==================

This repository contains the sources of the Katzenpost website.

Download
========

::

    git clone https://github.com/katzenpost/katzenpost/website.git
    cd website/docs
    git pull # update submodule
    cd ..

Build
=====

To build locally, install `sphinx
<http://www.sphinx-doc.org/en/stable/install.html>`_, then run ``make html`` (or ``make text`` for plaintext output)::

    pip install -U ablog sphinx
    make html
    make text
    xdg-open _build/html/index.html
    
Deploy
======

::

    ./publish.sh

License
=======

The content of this repository except images is licensed under the Creative Commons Attribution-ShareAlike 4.0 International License.

.. image:: https://i.creativecommons.org/l/by-sa/4.0/88x31.png
   :target: http://creativecommons.org/licenses/by-sa/4.0/
   :alt: Creative Commons Attribution-ShareAlike 4.0 International License
