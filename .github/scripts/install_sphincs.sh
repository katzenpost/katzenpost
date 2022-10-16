#!/bin/bash

git clone https://github.com/katzenpost/sphincsplus.git
cd sphincsplus/ref
make libsphincs
sudo make install
