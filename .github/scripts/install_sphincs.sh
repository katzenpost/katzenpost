#!/bin/bash

git clone https://github.com/katzenpost/katzenpost.git
cd katzenpost/sphincsplus/ref
make libsphincsplus.so
sudo make install
sudo ldconfig
cd ../..

