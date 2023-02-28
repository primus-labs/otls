#! /bin/bash
PWD=`pwd`
# ./config --prefix=${PWD}/../install_openssl/ -no-shared --debug && make -j  && make install
./config --prefix=${PWD}/../install_openssl/ -no-shared 
make -j4
