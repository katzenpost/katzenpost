#!/bin/bash

cd katzenpost/sphincsplus/ref
make libsphincsplus.so
sudo make install
sudo ldconfig
cd ../..

