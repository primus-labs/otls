#! /bin/bash
curdir=`pwd`


# Compile General TLS Server
cd ${curdir}/tls_server
./compile.sh

#
cd ${curdir}
mkdir -p ${curdir}/demo
cp ${curdir}/tls_server/tls_server ${curdir}/demo
