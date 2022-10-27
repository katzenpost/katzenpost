#!/bin/bash

git clone https://github.com/katzenpost/sphincsplus.git
cd sphincsplus/ref
make libsphincsplus.so
sudo make install
sudo ldconfig
cd ../..

