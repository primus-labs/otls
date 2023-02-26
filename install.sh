#! /bin/bash
CURRENT_PATH=`pwd`

#install openssl
git clone --recursive git@github.com:pado-labs/openssl.glt --branch ossl
cd openssl
./compile.sh

cd ${CURRENT_PATH}
git clone --recursive git@github.com:pado-labs/otls.git --branch xjq
cd otls
./compile.sh

